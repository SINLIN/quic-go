package congestion

import (
	"math"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

const (
	cubeScale                 = 40
	cubeCongestionWindowScale = 410
	cubeFactor                = 1 << cubeScale / cubeCongestionWindowScale / maxDatagramSize
	maxDatagramSize           = protocol.ByteCount(protocol.InitialPacketSize)
)

const defaultNumConnections = 1
const beta float32 = 0.7
const betaLastMax float32 = 0.85

type Cubic struct {
	clock                        Clock
	numConnections               int
	epoch                        monotime.Time
	lastMaxCongestionWindow      protocol.ByteCount
	ackedBytesCount              protocol.ByteCount
	estimatedTCPcongestionWindow protocol.ByteCount
	originPointCongestionWindow  protocol.ByteCount
	timeToOriginPoint            uint32
	lastTargetCongestionWindow   protocol.ByteCount
}

func NewCubic(clock Clock) *Cubic {
	c := &Cubic{
		clock:          clock,
		numConnections: defaultNumConnections,
	}
	c.Reset()
	return c
}

func (c *Cubic) Reset() {
	c.epoch = 0
	c.lastMaxCongestionWindow = 0
	c.ackedBytesCount = 0
	c.estimatedTCPcongestionWindow = 0
	c.originPointCongestionWindow = 0
	c.timeToOriginPoint = 0
	c.lastTargetCongestionWindow = 0
}

func (c *Cubic) alpha() float32 {
	b := c.beta()
	return 3 * float32(c.numConnections) * float32(c.numConnections) * (1 - b) / (1 + b)
}

func (c *Cubic) beta() float32 {
	return (float32(c.numConnections) - 1 + beta) / float32(c.numConnections)
}

func (c *Cubic) betaLastMax() float32 {
	return (float32(c.numConnections) - 1 + betaLastMax) / float32(c.numConnections)
}

func (c *Cubic) OnApplicationLimited() {
	c.epoch = 0
}

func (c *Cubic) CongestionWindowAfterPacketLoss(currentCongestionWindow protocol.ByteCount) protocol.ByteCount {
	if currentCongestionWindow+maxDatagramSize < c.lastMaxCongestionWindow {
		c.lastMaxCongestionWindow = protocol.ByteCount(c.betaLastMax() * float32(currentCongestionWindow))
	} else {
		c.lastMaxCongestionWindow = currentCongestionWindow
	}
	c.epoch = 0
	return protocol.ByteCount(float32(currentCongestionWindow) * c.beta())
}

func (c *Cubic) CongestionWindowAfterAck(
	ackedBytes protocol.ByteCount,
	currentCongestionWindow protocol.ByteCount,
	delayMin time.Duration,
	eventTime monotime.Time,
) protocol.ByteCount {
	c.ackedBytesCount += ackedBytes

	if c.epoch.IsZero() {
		c.epoch = eventTime
		c.ackedBytesCount = ackedBytes
		c.estimatedTCPcongestionWindow = currentCongestionWindow
		if c.lastMaxCongestionWindow <= currentCongestionWindow {
			c.timeToOriginPoint = 0
			c.originPointCongestionWindow = currentCongestionWindow
		} else {
			c.timeToOriginPoint = uint32(math.Cbrt(float64(cubeFactor * (c.lastMaxCongestionWindow - currentCongestionWindow))))
			c.originPointCongestionWindow = c.lastMaxCongestionWindow
		}
	}

	elapsedTime := int64(eventTime.Add(delayMin).Sub(c.epoch)/time.Microsecond) << 10 / (1000 * 1000)
	offset := int64(c.timeToOriginPoint) - elapsedTime
	if offset < 0 {
		offset = -offset
	}

	deltaCongestionWindow := protocol.ByteCount(cubeCongestionWindowScale*offset*offset*offset) * maxDatagramSize >> cubeScale
	var targetCongestionWindow protocol.ByteCount
	if elapsedTime > int64(c.timeToOriginPoint) {
		targetCongestionWindow = c.originPointCongestionWindow + deltaCongestionWindow
	} else {
		targetCongestionWindow = c.originPointCongestionWindow - deltaCongestionWindow
	}
	targetCongestionWindow = min(targetCongestionWindow, currentCongestionWindow+c.ackedBytesCount/2)
	c.estimatedTCPcongestionWindow += protocol.ByteCount(float32(c.ackedBytesCount) * c.alpha() * float32(maxDatagramSize) / float32(c.estimatedTCPcongestionWindow))
	c.ackedBytesCount = 0
	c.lastTargetCongestionWindow = targetCongestionWindow

	if targetCongestionWindow < c.estimatedTCPcongestionWindow {
		targetCongestionWindow = c.estimatedTCPcongestionWindow
	}
	return targetCongestionWindow
}

func (c *Cubic) SetNumConnections(n int) {
	c.numConnections = n
}
