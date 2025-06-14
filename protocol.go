package msproto

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"sync"

	"github.com/pkg/errors"
)

var (
	// 长度不够
	errDecodeLength = errors.New("decode length error")
)

// Protocol Protocol
type Protocol interface {
	// DecodeFrame 解码消息 返回frame 和 数据大小 和 error
	DecodeFrame(data []byte, version uint8) (Frame, int, error)
	// EncodeFrame 编码消息
	EncodeFrame(packet Frame, version uint8) ([]byte, error)
	// WriteFrame 编码报文，并写入writer
	WriteFrame(w Writer, packet Frame, version uint8) error
}

// WKroto 悟空IM协议对象
type MSProto struct {
	sync.RWMutex
}

// LatestVersion 最新版本
const LatestVersion = 4

// MaxRemaingLength 最大剩余长度 // 1<<28 - 1
const MaxRemaingLength uint32 = 1024 * 1024

// PayloadMaxSize 最大负载大小
const PayloadMaxSize = math.MaxInt16

// New 创建协议对象
func New() *MSProto {
	return &MSProto{}
}

// PacketDecodeFunc 包解码函数
type PacketDecodeFunc func(frame Frame, remainingBytes []byte, version uint8) (Frame, error)

// PacketEncodeFunc 包编码函数
type PacketEncodeFunc func(frame Frame, version uint8) ([]byte, error)

var packetDecodeMap = map[FrameType]PacketDecodeFunc{
	CONNECT:    decodeConnect,
	CONNACK:    decodeConnack,
	SEND:       decodeSend,
	SENDACK:    decodeSendack,
	RECV:       decodeRecv,
	RECVACK:    decodeRecvack,
	DISCONNECT: decodeDisConnect,
	SUB:        decodeSub,
	SUBACK:     decodeSuback,
}

// DecodePacketWithConn 解码包
func (l *MSProto) DecodePacketWithConn(conn io.Reader, version uint8) (Frame, error) {
	framer, err := l.decodeFramerWithConn(conn)
	if err != nil {
		return nil, err
	}
	// l.Debug("解码消息！", zap.String("framer", framer.String()))
	if framer.GetFrameType() == PING {
		return &PingPacket{}, nil
	}
	if framer.GetFrameType() == PONG {
		return &PongPacket{}, nil
	}
	if framer.RemainingLength > MaxRemaingLength {
		return nil, errors.New(fmt.Sprintf("消息超出最大限制[%d]！", MaxRemaingLength))
		// panic(errors.New(fmt.Sprintf("消息超出最大限制[%d]！", MaxRemaingLength)))
	}

	body := make([]byte, framer.RemainingLength)
	_, err = io.ReadFull(conn, body)
	if err != nil {
		return nil, err
	}
	decodeFunc := packetDecodeMap[framer.GetFrameType()]
	if decodeFunc == nil {
		return nil, errors.New(fmt.Sprintf("不支持对[%s]包的解码！", framer.GetFrameType()))
	}

	frame, err := decodeFunc(framer, body, version)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("解码包[%s]失败！", framer.GetFrameType()))
	}
	return frame, nil
}

// DecodePacket 解码包
func (l *MSProto) DecodeFrame(data []byte, version uint8) (Frame, int, error) {
	framer, remainingLengthLength, err := l.decodeFramer(data)
	if err != nil {
		return nil, 0, nil
	}
	frameType := framer.GetFrameType()
	if frameType == UNKNOWN {
		return nil, 0, nil
	}
	if frameType == PING {
		return &PingPacket{
			Framer: framer,
		}, 1, nil
	}
	if frameType == PONG {
		return &PongPacket{
			Framer: framer,
		}, 1, nil
	}

	if framer.RemainingLength > MaxRemaingLength {
		return nil, 0, fmt.Errorf("消息超出最大限制[%d]！", MaxRemaingLength)
	}
	msgLen := int(framer.RemainingLength) + 1 + remainingLengthLength
	if len(data) < msgLen {
		return nil, 0, nil
	}
	body := data[1+remainingLengthLength : msgLen]
	decodeFunc := packetDecodeMap[frameType]
	if decodeFunc == nil {
		return nil, 0, errors.New(fmt.Sprintf("不支持对[%s]包的解码！", frameType))
	}

	frame, err := decodeFunc(framer, body, version)
	if err != nil {
		return nil, 0, errors.Wrap(err, fmt.Sprintf("解码包[%s]失败！", frameType))
	}
	return frame, 1 + remainingLengthLength + int(framer.RemainingLength), nil
}

// EncodePacket 编码包
func (l *MSProto) EncodeFrame(frame Frame, version uint8) ([]byte, error) {
	buffer := bytes.NewBuffer([]byte{})
	err := l.encodeFrameWithWriter(buffer, frame, version)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// encodeFrameWithWriter 编码包
func (l *MSProto) encodeFrameWithWriter(w Writer, frame Frame, version uint8) error {
	frameType := frame.GetFrameType()
	enc := NewEncoderBuffer(w)
	defer enc.End()
	if frameType == PING || frameType == PONG {
		_ = enc.WriteByte(byte(int(frameType) << 4))
		return nil
	}

	var err error
	switch frameType {
	case CONNECT:
		packet := frame.(*ConnectPacket)
		l.encodeFrame(packet, enc, uint32(encodeConnectSize(packet, version)))
		err = encodeConnect(packet, enc, version)
	case CONNACK:
		packet := frame.(*ConnackPacket)
		l.encodeFrame(packet, enc, uint32(encodeConnackSize(packet, version)))
		err = encodeConnack(packet, enc, version)
	case SEND:
		packet := frame.(*SendPacket)
		if packet.Payload != nil && len(packet.Payload) > PayloadMaxSize {
			return errors.New(fmt.Sprintf("消息负载超出最大限制[%d]！", PayloadMaxSize))
		}
		l.encodeFrame(packet, enc, uint32(encodeSendSize(packet, version)))
		err = encodeSend(packet, enc, version)
	case SENDACK:
		packet := frame.(*SendackPacket)
		l.encodeFrame(packet, enc, uint32(encodeSendackSize(packet, version)))
		err = encodeSendack(packet, enc, version)
	case RECV:
		packet := frame.(*RecvPacket)
		l.encodeFrame(packet, enc, uint32(encodeRecvSize(packet, version)))
		err = encodeRecv(packet, enc, version)
	case RECVACK:
		packet := frame.(*RecvackPacket)
		l.encodeFrame(packet, enc, uint32(encodeRecvackSize(packet, version)))
		err = encodeRecvack(packet, enc, version)
	case DISCONNECT:
		packet := frame.(*DisconnectPacket)
		l.encodeFrame(packet, enc, uint32(encodeDisConnectSize(packet, version)))
		err = encodeDisConnect(packet, enc, version)
	case SUB:
		packet := frame.(*SubPacket)
		l.encodeFrame(packet, enc, uint32(encodeSubSize(packet, version)))
		err = encodeSub(packet, enc, version)
	case SUBACK:
		packet := frame.(*SubackPacket)
		l.encodeFrame(packet, enc, uint32(encodeSubackSize(packet, version)))
		err = encodeSuback(packet, enc, version)
	}
	if err != nil {
		return err
	}
	return nil
}

func (l *MSProto) WriteFrame(w Writer, packet Frame, version uint8) error {
	return l.encodeFrameWithWriter(w, packet, version)
}

func (l *MSProto) encodeFrame(f Frame, enc *Encoder, remainingLength uint32) {
	_ = enc.WriteByte(ToFixHeaderUint8(f))
	encodeVariable2(remainingLength, enc)
}

func (l *MSProto) decodeFramer(data []byte) (Framer, int, error) {
	typeAndFlags := data[0]
	p := FramerFromUint8(typeAndFlags)
	var remainingLengthLength uint32 = 0 // 剩余长度的长度
	var err error
	if p.FrameType != PING && p.FrameType != PONG {
		p.RemainingLength, remainingLengthLength, err = decodeLength(data[1:])
		if err != nil {
			if errors.Is(err, errDecodeLength) {
				return Framer{}, 0, nil
			}
			return Framer{}, 0, err
		}
	}
	p.FrameSize = int64(len(data))
	return p, int(remainingLengthLength), nil
}

func (l *MSProto) decodeFramerWithConn(conn io.Reader) (Framer, error) {
	b := make([]byte, 1)
	_, err := io.ReadFull(conn, b)
	if err != nil {
		return Framer{}, err
	}
	typeAndFlags := b[0]
	p := FramerFromUint8(typeAndFlags)
	if p.FrameType != PING && p.FrameType != PONG {
		p.RemainingLength = uint32(decodeLengthWithConn(conn))
	}
	return p, nil
}

func encodeVariable(size uint32) []byte {
	ret := make([]byte, 0, 10)
	for size > 0 {
		digit := byte(size % 0x80)
		size /= 0x80
		if size > 0 {
			digit |= 0x80
		}
		ret = append(ret, digit)
	}
	return ret
}

func encodeVariable2(size uint32, enc *Encoder) {
	for size > 0 {
		digit := byte(size % 0x80)
		size /= 0x80
		if size > 0 {
			digit |= 0x80
		}
		_ = enc.WriteByte(digit)
	}
}
func decodeLength(data []byte) (uint32, uint32, error) {
	var rLength uint32
	var multiplier uint32
	offset := 0
	for multiplier < 27 { //fix: Infinite '(digit & 128) == 1' will cause the dead loop
		if offset >= len(data) {
			return 0, 0, errDecodeLength
		}
		digit := data[offset]
		rLength |= uint32(digit&127) << multiplier
		if (digit & 128) == 0 {
			break
		}
		multiplier += 7
		offset++
	}
	return rLength, uint32(offset + 1), nil
}
func decodeLengthWithConn(r io.Reader) int {
	var rLength uint32
	var multiplier uint32
	for multiplier < 27 {
		b := make([]byte, 1)
		_, _ = io.ReadFull(r, b)
		digit := b[0]
		rLength |= uint32(digit&127) << multiplier
		if (digit & 128) == 0 {
			break
		}
		multiplier += 7
	}
	return int(rLength)
}

func encodeBool(b bool) (i int) {
	if b {
		i = 1
	}
	return
}
