using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes.Collections
{
    public class ThreadSafeList<T> : IList<T>
    {
        List<T> _collection = new List<T>();

        public T this[int index] { get => GetIndexedItem(index); set => SetIndexedItem(index, value); }


        private void SetIndexedItem(int index, T val)
        {
            lock(_collection)
            {
                _collection[index] = val;
            }
        }

        private T GetIndexedItem(int index)
        {
            T item;
            lock(_collection)
            {
                item = _collection[index];
            }
            return item;
        }

        public int Count()
        {
            int count = 0;
            lock(_collection)
            {
                count = _collection.Count;
            }
            return count;
        }

        public bool IsReadOnly => false;

        int ICollection<T>.Count => Count();

        public void Add(T obj)
        {
            lock(_collection)
            {
                _collection.Add(obj);
            }
        }

        public void Clear()
        {
            lock(_collection)
            {
                _collection.Clear();
            }
        }

        public bool Contains(T item)
        {
            bool bRet;
            lock(_collection)
            {
                bRet = _collection.Contains(item);
            }
            return bRet;
        }

        public void CopyTo(T[] array, int arrayIndex)
        {
            lock(_collection)
            {
                Buffer.BlockCopy(_collection.ToArray(), 0, array, arrayIndex, _collection.Count);
            }
        }

        public IEnumerator<T> GetEnumerator()
        {
            IEnumerator<T> res;
            lock(_collection)
            {
                res = _collection.GetEnumerator();
            }
            return res;
        }

        public int IndexOf(T item)
        {
            int i = -1;
            lock(_collection)
            {
                i = _collection.IndexOf(item);
            }
            return i;
        }

        public void Insert(int index, T item)
        {
            lock(_collection)
            {
                _collection[index] = item;
            }
        }

        public bool Remove(T obj)
        {
            bool bRet = false;
            lock(_collection)
            {
                bRet = _collection.Remove(obj);
            }
            return bRet;
        }

        public void RemoveAt(int index)
        {
            lock(_collection)
            {
                _collection.RemoveAt(index);
            }
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            IEnumerator res;
            lock(_collection)
            {
                res = _collection.GetEnumerator();
            }
            return res;
        }

        public T[] Flush()
        {
            T[] result;
            lock(_collection)
            {
                result = _collection.ToArray();
                _collection.Clear();
            }
            return result;
        }
    }
}
