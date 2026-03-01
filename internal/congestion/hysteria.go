package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

const (
	rttWindowSize = 10
	minStartBps   = 1024 * 1024 / 8 // 1Mbps 保护线
)

type hysteriaSender struct {
	rttStats *utils.RTTStats

	targetBps  protocol.ByteCount
	currentBps protocol.ByteCount
	stableBps  protocol.ByteCount

	maxDatagram  protocol.ByteCount
	nextSendTime monotime.Time

	// 历史 RTT 监控 (固定数组减少 GC)
	rttHistory [rttWindowSize]time.Duration
	rttIdx     int
	maxRTT     time.Duration

	rttCount int
}

func NewHysteriaSender(rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount, mbps int) SendAlgorithmWithDebugInfos {
	if mbps <= 0 {
		mbps = 10
	}
	targetBps := protocol.ByteCount(mbps) * 1024 * 1024 / 8

	// 起始速率策略：
	var initialBps protocol.ByteCount
	if mbps > 100 {
		initialBps = 100 * 1024 * 1024 / 8
	} else {
		initialBps = protocol.ByteCount(float64(targetBps) * 0.6)
	}

	// 健壮性保护：起始速率不得低于 1Mbps
	if initialBps < minStartBps {
		initialBps = minStartBps
	}

	return &hysteriaSender{
		rttStats:     rttStats,
		targetBps:    targetBps,
		currentBps:   initialBps,
		stableBps:    initialBps,
		maxDatagram:  initialMaxDatagramSize,
		nextSendTime: monotime.Now().Add(-100 * time.Millisecond),
	}
}

func (h *hysteriaSender) TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time {
	now := monotime.Now()
	if bytesInFlight >= h.GetCongestionWindow() {
		return now.Add(time.Hour)
	}
	if h.nextSendTime.After(now.Add(time.Millisecond)) {
		return h.nextSendTime
	}
	return 0
}

func (h *hysteriaSender) HasPacingBudget(now monotime.Time) bool {
	return !h.nextSendTime.After(now.Add(time.Millisecond))
}

func (h *hysteriaSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < h.GetCongestionWindow()
}

func (h *hysteriaSender) GetCongestionWindow() protocol.ByteCount {
	rtt := h.rttStats.SmoothedRTT()
	if rtt == 0 {
		return 1 * 1024 * 1024
	}

	// 动态 Multiplier：随 RTT 增加收紧窗口，强制更均匀的发包节奏
	multiplier := 1.5
	if rtt >= 180*time.Millisecond {
		multiplier = 1.1
	} else if rtt >= 100*time.Millisecond {
		multiplier = 1.3
	}

	cwnd := protocol.ByteCount(float64(h.currentBps) * rtt.Seconds() * multiplier)
	if minCwnd := 32 * h.maxDatagram; cwnd < minCwnd {
		return minCwnd
	}
	return cwnd
}

func (h *hysteriaSender) OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	interval := time.Duration(int64(bytes) * int64(time.Second) / int64(h.currentBps))
	now := monotime.Now()
	if h.nextSendTime.Before(now) {
		h.nextSendTime = now.Add(interval)
	} else {
		h.nextSendTime = h.nextSendTime.Add(interval)
	}

	// 动态 Burst Limit
	rtt := h.rttStats.LatestRTT()
	limitTime := 20 * time.Millisecond
	if halfRTT := rtt / 2; halfRTT > limitTime {
		limitTime = halfRTT
	}

	if limit := now.Add(limitTime); h.nextSendTime.After(limit) {
		h.nextSendTime = limit
	}
}

func (h *hysteriaSender) OnPacketAcked(pn protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
	h.updateRTTAndCheckJitter()

	rtt := h.rttStats.SmoothedRTT()
	// RTT 过大时（>150ms），加快速率增加步长，以快速填满长肥管道
	growFactor := 1.1
	if rtt > 150*time.Millisecond {
		growFactor = 1.25 // 加速探测
	}

	h.rttCount++
	// 每 4 个 RTT 探测周期
	if h.rttCount >= 4 {
		h.rttCount = 0
		if h.currentBps < h.targetBps {
			h.currentBps = protocol.ByteCount(float64(h.currentBps) * growFactor)
			if h.currentBps > h.targetBps {
				h.currentBps = h.targetBps
			}
		}
	}
}

func (h *hysteriaSender) OnCongestionEvent(pn protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
	rtt := h.rttStats.SmoothedRTT()

	// RTT 梯度丢包容忍度
	var threshold float64
	switch {
	case rtt < 50*time.Millisecond:
		threshold = 0.10
	case rtt < 100*time.Millisecond:
		threshold = 0.15
	case rtt < 180*time.Millisecond:
		threshold = 0.20
	default:
		threshold = 0.30
	}

	lossRate := float64(lostBytes) / float64(priorInFlight+1)

	// 判定：丢包超标则降速
	if lossRate > threshold {
		h.currentBps = protocol.ByteCount(float64(h.stableBps) * 0.75) // 降速 25%
		h.rttCount = -2                                                // 惩罚期
	} else {
		h.stableBps = h.currentBps
	}
}

func (h *hysteriaSender) updateRTTAndCheckJitter() {
	rtt := h.rttStats.LatestRTT()
	if rtt <= 0 {
		return
	}

	// 记录 RTT 历史
	h.rttHistory[h.rttIdx] = rtt
	h.rttIdx = (h.rttIdx + 1) % rttWindowSize
	if rtt > h.maxRTT {
		h.maxRTT = rtt
	}

	// 网络抖动快速下降：如果 LatestRTT 突增超过平滑 RTT 的 2 倍
	smoothed := h.rttStats.SmoothedRTT()
	if smoothed > 20*time.Millisecond && rtt > smoothed*2 {
		// 快速压制速率，减少网络抖动对缓冲区的冲击
		h.currentBps = protocol.ByteCount(float64(h.currentBps) * 0.85)
		if h.currentBps < minStartBps {
			h.currentBps = minStartBps
		}
	}
}

func (h *hysteriaSender) OnRetransmissionTimeout(bool)            { h.currentBps = minStartBps }
func (h *hysteriaSender) MaybeExitSlowStart()                     {}
func (h *hysteriaSender) SetMaxDatagramSize(s protocol.ByteCount) { h.maxDatagram = s }
func (h *hysteriaSender) InSlowStart() bool                       { return false }
func (h *hysteriaSender) InRecovery() bool                        { return false }
