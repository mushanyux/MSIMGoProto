package msproto

import (
	"fmt"
	"strconv"

	"github.com/pkg/errors"
	"github.com/valyala/bytebufferpool"
)

type StreamFlag uint8

const (
	StreamFlagStart StreamFlag = 0 // 开始
	StreamFlagIng   StreamFlag = 1 // 进行中
	StreamFlagEnd   StreamFlag = 2 // 结束
)

// RecvPacket 收到消息的包
type RecvPacket struct {
	Framer
	Setting     Setting
	MsgKey      string     // 用于验证此消息是否合法（仿中间人篡改）
	Expire      uint32     // 消息过期时间 0 表示永不过期
	MessageID   int64      // 服务端的消息ID(全局唯一)
	MessageSeq  uint32     // 消息序列号 （用户唯一，有序递增）
	ClientMsgNo string     // 客户端唯一标示
	StreamNo    string     // 流式编号
	StreamId    uint64     // 流式序列号
	StreamFlag  StreamFlag // 流式标示
	Timestamp   int32      // 服务器消息时间戳(10位，到秒)
	ChannelID   string     // 频道ID
	ChannelType uint8      // 频道类型
	Topic       string     // 话题ID
	FromUID     string     // 发送者UID
	Payload     []byte     // 消息内容

	// ---------- 以下不参与编码 ------------
	ClientSeq uint64 // 客户端提供的序列号，在客户端内唯一
}

func (r *RecvPacket) Reset() {
	r.Framer.FrameType = UNKNOWN
	r.Framer.RemainingLength = 0
	r.Framer.NoPersist = false
	r.Framer.RedDot = false
	r.Framer.SyncOnce = false
	r.Framer.DUP = false
	r.Framer.HasServerVersion = false
	r.Framer.FrameSize = 0
	r.Setting = 0
	r.MsgKey = ""
	r.Expire = 0
	r.MessageID = 0
	r.MessageSeq = 0
	r.ClientMsgNo = ""
	r.StreamNo = ""
	r.StreamId = 0
	r.StreamFlag = 0
	r.Timestamp = 0
	r.ChannelID = ""
	r.ChannelType = 0
	r.Topic = ""
	r.FromUID = ""
	r.Payload = nil
	r.ClientSeq = 0
}

// GetPacketType 获得包类型
func (r *RecvPacket) GetFrameType() FrameType {
	return RECV
}

func (r *RecvPacket) Size() int {
	return r.SizeWithProtoVersion(LatestVersion)
}

func (r *RecvPacket) SizeWithProtoVersion(protVersion uint8) int {
	return encodeRecvSize(r, protVersion)
}

func (r *RecvPacket) VerityString() string {
	// 从池中获取一个字节缓冲区
	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf) // 使用完成后归还到池中
	buf.Reset()
	r.VerityBytes(buf)
	return string(buf.Bytes())
}

func (r *RecvPacket) VerityBytes(buf *bytebufferpool.ByteBuffer) {
	buf.B = strconv.AppendInt(buf.B, r.MessageID, 10)
	buf.B = strconv.AppendUint(buf.B, uint64(r.MessageSeq), 10)
	buf.B = append(buf.B, r.ClientMsgNo...)
	buf.B = strconv.AppendInt(buf.B, int64(r.Timestamp), 10)
	buf.B = append(buf.B, r.FromUID...)
	buf.B = append(buf.B, r.ChannelID...)
	buf.B = strconv.AppendInt(buf.B, int64(r.ChannelType), 10)
	buf.B = append(buf.B, r.Payload...)

}

func (r *RecvPacket) String() string {
	return fmt.Sprintf("recv Header:%s Setting:%d MessageID:%d MessageSeq:%d Timestamp:%d Expire:%d FromUid:%s ChannelID:%s ChannelType:%d Topic:%s Payload:%s", r.Framer, r.Setting, r.MessageID, r.MessageSeq, r.Timestamp, r.Expire, r.FromUID, r.ChannelID, r.ChannelType, r.Topic, string(r.Payload))
}

func decodeRecv(frame Frame, data []byte, version uint8) (Frame, error) {
	dec := NewDecoder(data)
	recvPacket := &RecvPacket{}
	recvPacket.Framer = frame.(Framer)
	var err error
	setting, err := dec.Uint8()
	if err != nil {
		return nil, errors.Wrap(err, "解码消息设置失败！")
	}
	recvPacket.Setting = Setting(setting)
	// MsgKey
	if recvPacket.MsgKey, err = dec.String(); err != nil {
		return nil, errors.Wrap(err, "解码MsgKey失败！")
	}
	// 发送者
	if recvPacket.FromUID, err = dec.String(); err != nil {
		return nil, errors.Wrap(err, "解码FromUID失败！")
	}
	// 频道ID
	if recvPacket.ChannelID, err = dec.String(); err != nil {
		return nil, errors.Wrap(err, "解码ChannelId失败！")
	}
	// 频道类型
	if recvPacket.ChannelType, err = dec.Uint8(); err != nil {
		return nil, errors.Wrap(err, "解码ChannelType失败！")
	}
	if version >= 3 {
		var expire uint32
		if expire, err = dec.Uint32(); err != nil {
			return nil, errors.Wrap(err, "解码Expire失败！")
		}
		recvPacket.Expire = expire
	}
	// 客户端唯一标示
	if recvPacket.ClientMsgNo, err = dec.String(); err != nil {
		return nil, errors.Wrap(err, "解码ClientMsgNo失败！")
	}
	// 流消息
	if version >= 2 && recvPacket.Setting.IsSet(SettingStream) {
		var streamFlag uint8
		if streamFlag, err = dec.Uint8(); err != nil {
			return nil, errors.Wrap(err, "解码StreamFlag失败！")
		}
		recvPacket.StreamFlag = StreamFlag(streamFlag)

		if recvPacket.StreamNo, err = dec.String(); err != nil {
			return nil, errors.Wrap(err, "解码StreamNo失败！")
		}
		if recvPacket.StreamId, err = dec.Uint64(); err != nil {
			return nil, errors.Wrap(err, "解码StreamId失败！")
		}
	}
	// 消息全局唯一ID
	if recvPacket.MessageID, err = dec.Int64(); err != nil {
		return nil, errors.Wrap(err, "解码MessageId失败！")
	}
	// 消息序列号 （用户唯一，有序递增）
	if recvPacket.MessageSeq, err = dec.Uint32(); err != nil {
		return nil, errors.Wrap(err, "解码MessageSeq失败！")
	}
	// 消息时间
	if recvPacket.Timestamp, err = dec.Int32(); err != nil {
		return nil, errors.Wrap(err, "解码Timestamp失败！")
	}
	if recvPacket.Setting.IsSet(SettingTopic) {
		// topic
		if recvPacket.Topic, err = dec.String(); err != nil {
			return nil, errors.Wrap(err, "解密topic消息失败！")
		}
	}
	if recvPacket.Payload, err = dec.BinaryAll(); err != nil {
		return nil, errors.Wrap(err, "解码payload失败！")
	}
	return recvPacket, err
}

func encodeRecv(recvPacket *RecvPacket, enc *Encoder, version uint8) error {
	// setting
	_ = enc.WriteByte(recvPacket.Setting.Uint8())
	// MsgKey
	enc.WriteString(recvPacket.MsgKey)
	// 发送者
	enc.WriteString(recvPacket.FromUID)
	// 频道ID
	enc.WriteString(recvPacket.ChannelID)
	// 频道类型
	enc.WriteUint8(recvPacket.ChannelType)
	if version >= 3 {
		enc.WriteUint32(recvPacket.Expire)
	}
	// 客户端唯一标示
	enc.WriteString(recvPacket.ClientMsgNo)
	// 流消息
	if version >= 2 && recvPacket.Setting.IsSet(SettingStream) {
		enc.WriteUint8(uint8(recvPacket.StreamFlag))
		enc.WriteString(recvPacket.StreamNo)
		enc.WriteUint64(recvPacket.StreamId)
	}
	// 消息唯一ID
	enc.WriteInt64(recvPacket.MessageID)
	// 消息有序ID
	enc.WriteUint32(recvPacket.MessageSeq)
	// 消息时间戳
	enc.WriteInt32(recvPacket.Timestamp)
	if recvPacket.Setting.IsSet(SettingTopic) {
		enc.WriteString(recvPacket.Topic)
	}
	// 消息内容
	enc.WriteBytes(recvPacket.Payload)
	return nil
}

func encodeRecvSize(packet *RecvPacket, version uint8) int {
	size := 0
	size += SettingByteSize
	size += (len(packet.MsgKey) + StringFixLenByteSize)
	size += (len(packet.FromUID) + StringFixLenByteSize)
	size += (len(packet.ChannelID) + StringFixLenByteSize)
	size += ChannelTypeByteSize
	if version >= 3 {
		size += ExpireByteSize
	}
	size += (len(packet.ClientMsgNo) + StringFixLenByteSize)
	if version >= 2 && packet.Setting.IsSet(SettingStream) {
		size += StreamFlagByteSize
		size += (len(packet.StreamNo) + StringFixLenByteSize)
		size += StreamIdByteSize
	}
	size += MessageIDByteSize
	size += MessageSeqByteSize
	size += TimestampByteSize
	if packet.Setting.IsSet(SettingTopic) {
		size += (len(packet.Topic) + StringFixLenByteSize)
	}
	size += len(packet.Payload)
	return size
}
