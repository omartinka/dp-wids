package connectors

import (
  "net"
  "wids/context"
)

type WidsTcpClient struct {
  conn    *net.TCPConn
  address string
}

func NewWidsTcpClient() (*WidsTcpClient, error) {
  tcpAddr, err := net.ResolveTCPAddr("tcp", context.WidsAddress)
  if err != nil {
    return nil, err
  }
  
  conn, err := net.DialTCP("tcp", nil, tcpAddr)
  if err != nil {
    return nil, err
  }

  return &WidsTcpClient{
    conn:     conn,
    address:  context.WidsAddress,
  }, nil
}

func (c *WidsTcpClient) SendData(data []byte) error {
  _, err := c.conn.Write(data)
  return err
}

type WidsClient struct {
  tcpClient *WidsTcpClient
  // udpClient *WidsUdpClient
}

func NewWidsClient() (*WidsClient, error) {
  var tcpClient *WidsTcpClient = nil
  // udpClient = nil
  var err error = nil
  
  if context.IsTcpWids {
    tcpClient, err = NewWidsTcpClient()
  }

  if err != nil {
    return nil, err
  }

  /*
  if context.IsUdp {

  }
  */
  return &WidsClient{
    tcpClient: tcpClient,
  }, nil
}

func (wc *WidsClient) IsOk() bool {
  if context.IsTcpWids && wc.tcpClient != nil {
    return true
  }
  return false
}

func (wc *WidsClient) SendFrame(data []byte) error {
  if wc.IsOk() {
    if context.IsTcpWids {
      wc.tcpClient.SendData(data)
    }
  } else {
    log.Error("connection to wids analyzer broken!")
  }

  return nil
}

var WidsConnector *WidsClient = nil

func InitWidsConn() {
  widsConnector, err := NewWidsClient()
  if err != nil {
    log.Error(err)
  } else {
    log.Info("connection to WIDS analyzer initialized")
  }
  WidsConnector = widsConnector
}

