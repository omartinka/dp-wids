package util

import (
	"container/list"
)

type QLifo struct {
  idMap    map[int]int
	list     *list.List
	maxSize  int
}

func QLifo(maxSize int) *QLifo {
	return &QLifo{
    idMap:   make(map[int]int),
    list:    list.New(),
		maxSize: maxSize,
	}
}

func (q *QLifo) Push(item interface{}) {
	if q.list.Len() >= q.maxSize {
		// Remove the oldest item if the queue is full
    firstElem := q.list.Front()
    delete(q.idMap, firstElem.Value)
    q.list.Remove(q.list.Front())
	}
	q.list.PushBack(item)
  q.idMap[item] = 1
}

func (q *QLifo) Pop() interface{} {
	if q.list.Len() == 0 {
		return nil
	}
	lastElement := q.list.Back()
  delete(q.idMap, lastElement.Value)
	q.list.Remove(lastElement)
	return lastElement.Value
}

func (q *QLifo) Contains(item interface{}) bool {
  _ ok := q.idMap[item]
  return ok
}


type Deduplicator struct () {
  channelMap map[int]*QLifo
}

func Deduplicator() *Deduplicator {
  return &Deduplicator{}
}

func (d *Deduplicator) Add(channel int, id int) {
  val, ok := d.channelMap[channel]

  if !ok {
    d.channelMap[channel] := QLifo(512);
  }

  d.channelMap[channel].Push(id)
}

func (d *Deduplicator) Check(channel int, id int) bool {
  queue, ok := d.channelMap[channel]

  if !ok {
    return false
  }

  return queue.Contains(id)
}

