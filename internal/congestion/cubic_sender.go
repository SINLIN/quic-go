package congestion

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

const (
	initialMaxDatagramSize     = protocol.ByteCount(protocol.InitialPacketSize)
	maxBurstPackets            = 3
	renoBeta                   = 0.7
	minCongestionWindowPackets = 2
	initialCongestionWindow    = 32

	// 新增：功能优化常量
	minBandwidthLimit      = 5 * 1024 * 1024 // 5Mbps
	lossToleranceThreshold = 0.10            // 10% 丢包容忍度
)

type cubicSender struct {
	hybridSlowStart HybridSlowStart
	rttStats        *utils.RTTStats
	connStats       *utils.ConnectionStats
	cubic           *Cubic
	pacer           *pacer
	clock           Clock

	reno bool

	largestSentPacketNumber  protocol.PacketNumber
	largestAckedPacketNumber protocol.PacketNumber
	largestSentAtLastCutback protocol.PacketNumber

	lastCutbackExitedSlowstart bool
	congestionWindow           protocol.ByteCount
	slowStartThreshold         protocol.ByteCount
	numAckedPackets            uint64

	initialCongestionWindow    protocol.ByteCount
	initialMaxCongestionWindow protocol.ByteCount

	maxDatagramSize protocol.ByteCount

	lastState qlog.CongestionState
	qlogger   qlogwriter.Recorder
}

var (
	_ SendAlgorithm               = &cubicSender{}
	_ SendAlgorithmWithDebugInfos = &cubicSender{}
)

func NewCubicSender(clock Clock, rttStats *utils.RTTStats, connStats *utils.ConnectionStats, initialMaxDatagramSize protocol.ByteCount, reno bool, qlogger qlogwriter.Recorder) *cubicSender {
	return newCubicSender(clock, rttStats, connStats, reno, initialMaxDatagramSize, initialCongestionWindow*initialMaxDatagramSize, protocol.MaxCongestionWindowPackets*initialMaxDatagramSize, qlogger)
}

func newCubicSender(clock Clock, rttStats *utils.RTTStats, connStats *utils.ConnectionStats, reno bool, initialMaxDatagramSize, initialCongestionWindow, initialMaxCongestionWindow protocol.ByteCount, qlogger qlogwriter.Recorder) *cubicSender {
	c := &cubicSender{
		rttStats:                   rttStats,
		connStats:                  connStats,
		largestSentPacketNumber:    protocol.InvalidPacketNumber,
		largestAckedPacketNumber:   protocol.InvalidPacketNumber,
		largestSentAtLastCutback:   protocol.InvalidPacketNumber,
		initialCongestionWindow:    initialCongestionWindow,
		initialMaxCongestionWindow: initialMaxCongestionWindow,
		congestionWindow:           initialCongestionWindow,
		slowStartThreshold:         protocol.MaxByteCount,
		cubic:                      NewCubic(clock),
		clock:                      clock,
		reno:                       reno,
		qlogger:                    qlogger,
		maxDatagramSize:            initialMaxDatagramSize,
	}
	c.pacer = newPacer(c.BandwidthEstimate)
	if c.qlogger != nil {
		c.lastState = qlog.CongestionStateSlowStart
		c.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart})
	}
	return c
}

func (c *cubicSender) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	return c.pacer.TimeUntilSend()
}
func (c *cubicSender) HasPacingBudget(now monotime.Time) bool {
	return c.pacer.Budget(now) >= c.maxDatagramSize
}
func (c *cubicSender) maxCongestionWindow() protocol.ByteCount {
	return c.maxDatagramSize * protocol.MaxCongestionWindowPackets
}
func (c *cubicSender) minCongestionWindow() protocol.ByteCount {
	return c.maxDatagramSize * minCongestionWindowPackets
}

func (c *cubicSender) OnPacketSent(sentTime monotime.Time, _ protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	c.pacer.SentPacket(sentTime, bytes)
	if !isRetransmittable {
		return
	}
	c.largestSentPacketNumber = packetNumber
	c.hybridSlowStart.OnPacketSent(packetNumber)
}

func (c *cubicSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < c.GetCongestionWindow()
}
func (c *cubicSender) InRecovery() bool {
	return c.largestAckedPacketNumber != protocol.InvalidPacketNumber && c.largestAckedPacketNumber <= c.largestSentAtLastCutback
}
func (c *cubicSender) InSlowStart() bool                       { return c.GetCongestionWindow() < c.slowStartThreshold }
func (c *cubicSender) GetCongestionWindow() protocol.ByteCount { return c.congestionWindow }
func (c *cubicSender) MaybeExitSlowStart() {
	if c.InSlowStart() && c.hybridSlowStart.ShouldExitSlowStart(c.rttStats.LatestRTT(), c.rttStats.MinRTT(), c.GetCongestionWindow()/c.maxDatagramSize) {
		c.slowStartThreshold = c.congestionWindow
		c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	}
}

func (c *cubicSender) OnPacketAcked(ackedPacketNumber protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	c.largestAckedPacketNumber = max(ackedPacketNumber, c.largestAckedPacketNumber)
	if c.InRecovery() {
		return
	}
	c.maybeIncreaseCwnd(ackedPacketNumber, ackedBytes, priorInFlight, eventTime)
	if c.InSlowStart() {
		c.hybridSlowStart.OnPacketAcked(ackedPacketNumber)
	}
}

// 核心优化：OnCongestionEvent
func (c *cubicSender) OnCongestionEvent(packetNumber protocol.PacketNumber, lostBytes, priorInFlight protocol.ByteCount) {
	c.connStats.PacketsLost.Add(1)
	c.connStats.BytesLost.Add(uint64(lostBytes))

	if packetNumber <= c.largestSentAtLastCutback {
		return
	}

	// 优化1：10% 丢包容忍度
	// 使用 connStats 中的总发送字节和总丢包字节计算丢包率
	totalSent := c.connStats.BytesSent.Load()
	totalLost := c.connStats.BytesLost.Load()
	if totalSent > 0 && float64(totalLost)/float64(totalSent) < lossToleranceThreshold {
		// 丢包率低于10%，视为网络抖动或非拥塞丢包，不进行窗口削减
		return
	}

	c.lastCutbackExitedSlowstart = c.InSlowStart()
	c.maybeQlogStateChange(qlog.CongestionStateRecovery)

	if c.reno {
		c.congestionWindow = protocol.ByteCount(float64(c.congestionWindow) * renoBeta)
	} else {
		c.congestionWindow = c.cubic.CongestionWindowAfterPacketLoss(c.congestionWindow)
	}

	// 优化2：5Mbps 最小速率保护
	c.applyMinRateProtection()

	c.slowStartThreshold = c.congestionWindow
	c.largestSentAtLastCutback = c.largestSentPacketNumber
	c.numAckedPackets = 0
}

// applyMinRateProtection 确保 CWND 不低于维持 5Mbps 所需的 BDP
func (c *cubicSender) applyMinRateProtection() {
	srtt := c.rttStats.SmoothedRTT()
	if srtt <= 0 {
		srtt = 100 * time.Millisecond // 兜底 RTT
	}
	// BDP = (Bandwidth in bps * RTT in seconds) / 8 bits per byte
	minCwnd := protocol.ByteCount((float64(minBandwidthLimit) * srtt.Seconds()) / 8)

	// 取系统默认最小窗口与 5Mbps 对应窗口的较大值
	absoluteMin := c.minCongestionWindow()
	if minCwnd < absoluteMin {
		minCwnd = absoluteMin
	}

	if c.congestionWindow < minCwnd {
		c.congestionWindow = minCwnd
	}
}

func (c *cubicSender) maybeIncreaseCwnd(_ protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	if !c.isCwndLimited(priorInFlight) {
		c.cubic.OnApplicationLimited()
		c.maybeQlogStateChange(qlog.CongestionStateApplicationLimited)
		return
	}
	if c.congestionWindow >= c.maxCongestionWindow() {
		return
	}
	if c.InSlowStart() {
		c.congestionWindow += c.maxDatagramSize
		c.maybeQlogStateChange(qlog.CongestionStateSlowStart)
		return
	}
	c.maybeQlogStateChange(qlog.CongestionStateCongestionAvoidance)
	if c.reno {
		c.numAckedPackets++
		if c.numAckedPackets >= uint64(c.congestionWindow/c.maxDatagramSize) {
			c.congestionWindow += c.maxDatagramSize
			c.numAckedPackets = 0
		}
	} else {
		c.congestionWindow = min(c.maxCongestionWindow(), c.cubic.CongestionWindowAfterAck(ackedBytes, c.congestionWindow, c.rttStats.MinRTT(), eventTime))
	}
}

func (c *cubicSender) isCwndLimited(bytesInFlight protocol.ByteCount) bool {
	congestionWindow := c.GetCongestionWindow()
	if bytesInFlight >= congestionWindow {
		return true
	}
	availableBytes := congestionWindow - bytesInFlight
	slowStartLimited := c.InSlowStart() && bytesInFlight > congestionWindow/2
	return slowStartLimited || availableBytes <= maxBurstPackets*c.maxDatagramSize
}

func (c *cubicSender) BandwidthEstimate() Bandwidth {
	srtt := c.rttStats.SmoothedRTT()
	if srtt == 0 {
		srtt = protocol.TimerGranularity
	}
	return BandwidthFromDelta(c.GetCongestionWindow(), srtt)
}

func (c *cubicSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	c.largestSentAtLastCutback = protocol.InvalidPacketNumber
	if !packetsRetransmitted {
		return
	}
	c.hybridSlowStart.Restart()
	c.cubic.Reset()
	c.slowStartThreshold = c.congestionWindow / 2
	c.congestionWindow = c.minCongestionWindow()
	// 超时也应用 5Mbps 保护
	c.applyMinRateProtection()
}

func (c *cubicSender) OnConnectionMigration() {
	c.hybridSlowStart.Restart()
	c.largestSentPacketNumber = protocol.InvalidPacketNumber
	c.largestAckedPacketNumber = protocol.InvalidPacketNumber
	c.largestSentAtLastCutback = protocol.InvalidPacketNumber
	c.lastCutbackExitedSlowstart = false
	c.cubic.Reset()
	c.numAckedPackets = 0
	c.congestionWindow = c.initialCongestionWindow
	c.slowStartThreshold = c.initialMaxCongestionWindow
}

func (c *cubicSender) maybeQlogStateChange(new qlog.CongestionState) {
	if c.qlogger == nil || new == c.lastState {
		return
	}
	c.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: new})
	c.lastState = new
}

func (c *cubicSender) SetMaxDatagramSize(s protocol.ByteCount) {
	if s < c.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", c.maxDatagramSize, s))
	}
	cwndIsMinCwnd := c.congestionWindow == c.minCongestionWindow()
	c.maxDatagramSize = s
	if cwndIsMinCwnd {
		c.congestionWindow = c.minCongestionWindow()
	}
	c.pacer.SetMaxDatagramSize(s)
}
