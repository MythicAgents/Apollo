using ApolloInterop.Classes.Events;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ApolloInterop.Classes.IO
{
	public class EventableStringWriter : StringWriter
	{
		public event EventHandler<StringDataEventArgs> BufferWritten;

		public override void Write(char[] buffer, int index, int count)
		{
			string value = new string(buffer.Skip(index).Take(count).ToArray());
			BufferWritten?.Invoke(this, new StringDataEventArgs(value));
			base.Write(buffer, index, count);
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
	}
}
