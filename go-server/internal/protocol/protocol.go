package protocol

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
)

// SendMsg 向指定的连接发送消息
// 消息会被序列化为JSON，并在前面加上一个4字节的长度前缀
func SendMsg(conn net.Conn, msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// 创建一个4字节的头部来存储消息长度
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))

	// 首先发送头部
	if _, err := conn.Write(header); err != nil {
		return err
	}

	// 然后发送消息体
	if _, err := conn.Write(data); err != nil {
		return err
	}

	return nil
}

// RecvMsg 从指定的连接接收消息
// 它首先读取4字节的长度前缀，然后读取完整的消息体并解码为JSON
func RecvMsg(conn net.Conn) (map[string]interface{}, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	msgLen := binary.BigEndian.Uint32(header)

	data := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		// 如果JSON解码失败，尝试将其作为普通字符串返回
		// 这对于处理某些非JSON格式的响应（尽管我们的协议主要是JSON）可能有用
		return map[string]interface{}{"data": string(data)}, nil
	}

	return msg, nil
}
