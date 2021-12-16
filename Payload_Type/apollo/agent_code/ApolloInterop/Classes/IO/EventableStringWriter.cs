using ApolloInterop.Classes.Events;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes.IO
{
	public class EventableStringWriter : StringWriter
	{
		public event EventHandler<StringDataEventArgs> BufferWritten;

        private bool IsRecursive()
        {
            StackTrace st = new StackTrace();
            StackFrame[] frames = st.GetFrames();
            if (frames.Length < 4)
            {
                return false;
            }
            StackFrame f1 = frames[3];
            if (f1.GetMethod().ReflectedType == typeof(EventableStringWriter))
            {
                return true;
            } else
            {
                return false;
            }
        }

        private void OnBufferWrite(StringDataEventArgs args)
        {
            if (!IsRecursive())
            {
                BufferWritten?.Invoke(this, args);
            }
        }

        public override void Write(string value)
        {
			BufferWritten?.Invoke(this, new StringDataEventArgs(value));
            base.Write(value);
        }

        public override void Write(char[] buffer, int index, int count)
		{
            string value = new string(buffer.Skip(index).Take(count).ToArray());
			OnBufferWrite(new StringDataEventArgs(value));
			base.Write(buffer, index, count);
		}

        public override void Write(char[] buffer)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(new string(buffer)));
            base.Write(buffer);
        }

        public override void Write(bool value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString()));
            base.Write(value);
        }

        public override void Write(int value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString()));
            base.Write(value);
        }

        public override void Write(uint value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString()));
            base.Write(value);
        }

        public override void Write(long value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString()));
            base.Write(value);
        }

        public override void Write(ulong value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString()));
            base.Write(value);
        }

        public override void Write(float value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString()));
            base.Write(value);
        }

        public override void Write(double value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString()));
            base.Write(value);
        }

        public override void Write(decimal value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString()));
            base.Write(value);
        }

        public override void Write(object value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString()));
            base.Write(value);
        }

        public override void Write(string format, object arg0)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(string.Format(format, arg0)));
            base.Write(format, arg0);
        }

        public override void Write(string format, object arg0, object arg1)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(string.Format(format, arg0, arg1)));
            base.Write(format, arg0, arg1);
        }

        public override void Write(string format, object arg0, object arg1, object arg2)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(string.Format(format, arg0, arg1, arg2)));
            base.Write(format, arg0, arg1, arg2);
        }

        public override void Write(string format, params object[] arg)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(string.Format(format, arg)));
            base.Write(format, arg);
        }

        public override void Write(char value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString()));
            base.Write(value);
        }

        public override void WriteLine(char[] buffer, int index, int count)
		{
			string value = new string(buffer.Skip(0).Take(count).ToArray());
			BufferWritten?.Invoke(this, new StringDataEventArgs(value + "\r\n"));
			base.WriteLine(buffer, index, count);
		}

		public override void WriteLine()
		{
			BufferWritten?.Invoke(this, new StringDataEventArgs("\r\n"));
			base.WriteLine();
		}

        public override void WriteLine(char value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString() + "\r\n"));
            base.WriteLine(value);
        }

        public override void WriteLine(char[] buffer)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(new string(buffer) + "\r\n"));
            base.WriteLine(buffer);
        }

        public override void WriteLine(bool value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString() + "\r\n"));
            base.WriteLine(value);
        }

        public override void WriteLine(int value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString() + "\r\n"));
            base.WriteLine(value);
        }

        public override void WriteLine(uint value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString() + "\r\n"));
            base.WriteLine(value);
        }

        public override void WriteLine(long value)
        {
            base.WriteLine(value);
        }

        public override void WriteLine(ulong value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString() + "\r\n"));
            base.WriteLine(value);
        }

        public override void WriteLine(float value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString() + "\r\n"));
            base.WriteLine(value);
        }

        public override void WriteLine(double value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString() + "\r\n"));
            base.WriteLine(value);
        }

        public override void WriteLine(decimal value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString() + "\r\n"));
            base.WriteLine(value);
        }

        public override void WriteLine(string value)
        {
            OnBufferWrite(new StringDataEventArgs(value.ToString() + "\r\n"));
            base.WriteLine(value);
        }

        public override void WriteLine(object value)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(value.ToString() + "\r\n"));
            base.WriteLine(value);
        }

        public override void WriteLine(string format, object arg0)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(string.Format(format, arg0) + "\r\n"));
            base.WriteLine(format, arg0);
        }

        public override void WriteLine(string format, object arg0, object arg1)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(string.Format(format, arg0, arg1) + "\r\n"));
            base.WriteLine(format, arg0, arg1);
        }

        public override void WriteLine(string format, object arg0, object arg1, object arg2)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(string.Format(format, arg0, arg1, arg2) + "\r\n"));
            base.WriteLine(format, arg0, arg1, arg2);
        }

        public override void WriteLine(string format, params object[] arg)
        {
            BufferWritten?.Invoke(this, new StringDataEventArgs(string.Format(format, arg) + "\r\n"));
            base.WriteLine(format, arg);
        }
    }
}
