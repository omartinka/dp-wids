package handlers

import (
	"container/list"
)

type lQueue struct {
  idMap    map[int]int
	list     *list.List
	maxSize  int
}

func NewlQueue(maxSize int) *lQueue {
	return &lQueue{
    idMap:   make(map[int]int),
		list:    list.New(),
		maxSize: maxSize,
	}
}

func (q *lQueue) Push(item interface{}) {
	if q.list.Len() >= q.maxSize {
    item_ := q.list.Front()
    delete(q.idMap, item_.Value.(int))
		q.list.Remove(item_)
	}
	q.list.PushBack(item)
  q.idMap[item.(int)] = 1
}

func (q *lQueue) Pop() interface{} {
	if q.list.Len() == 0 {
		return nil
	}
	lastElement := q.list.Back()
	q.list.Remove(lastElement)
  
  delete(q.idMap, lastElement.Value.(int))
	return lastElement.Value
}

type Deduplicator struct {
  queue map[int]*lQueue
  channels int
}

func NewDeduplicator() *Deduplicator {
  return &Deduplicator{
    queue: make(map[int]*lQueue),
    channels: 123,
  }
}

func (d *Deduplicator) Check(channel int, snum int) bool {
  queue, ok := d.queue[channel]

  if !ok {
    return false
  }

  _, ok = queue.idMap[snum]
  return ok
}

func (d *Deduplicator) Add(channel int, snum int) {
  _, ok := d.queue[channel]
  if !ok {
    d.queue[channel] = NewlQueue(512)
  }

  d.queue[channel].Push(snum)
}
