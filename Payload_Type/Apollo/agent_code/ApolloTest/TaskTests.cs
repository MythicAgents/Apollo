using System;
using System.Collections.Generic;
using Apollo;
using Apollo.Jobs;
using Apollo.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ApolloTests
{
    [TestClass]
    public class TaskTests
    {
        // This method requires a file named test.txt in C:\Users\Public
        // It expects the file contents to be "test file"
        [TestMethod]
        public void CatTest()
        {
            if (!System.IO.File.Exists("C:\\Users\\Public\\test.txt"))
            {
                using (System.IO.FileStream fs = System.IO.File.Create("C:\\Users\\Public\\test.txt"))
                {
                    using (System.IO.StreamWriter sw = new System.IO.StreamWriter(fs))
                    {
                        sw.WriteLine("test file");
                    }
                }
            }    
            Task task = new Task("cat", "C:\\Users\\Public\\test.txt", "1");
            Job job = new Job(task, null);
            Cat.Execute(job, null);
            // Ensure the task is marked complete
            Assert.IsTrue(task.status == "complete");
            // Ensure the output matches expected output from the test file
            Assert.AreEqual("test file", task.message);
        }
        [TestMethod]
        public void CatTestInvalid()
        {
            Task task = new Task("cat", "C:\\balahsdghaseter.txt", "1");
            Job job = new Job(task, null);
            Cat.Execute(job, null);
            // Ensure the task is marked complete
            Assert.IsTrue(task.status == "error");
        }
        [TestMethod]
        public void CdTest()
        {
            // Ensure we're in a different directory
            System.IO.Directory.SetCurrentDirectory("C:\\");
            Task task = new Task("cd", "C:\\Users\\Public", "1");
            Job job = new Job(task, null);
            ChangeDir.Execute(job, null);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "complete");
            // Ensure the current working directory has changed
            Assert.AreEqual("C:\\Users\\Public", Environment.CurrentDirectory);
            // Change working directory back
            System.IO.Directory.SetCurrentDirectory("C:\\");
        }
        [TestMethod]
        public void CdTestInvalid()
        {
            // Ensure we're in a different directory
            System.IO.Directory.SetCurrentDirectory("C:\\");
            Task task = new Task("cd", "C:\\asdfasdthetherhasdf", "1");
            Job job = new Job(task, null);
            ChangeDir.Execute(job, null);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "error");
            // Change working directory back
            System.IO.Directory.SetCurrentDirectory("C:\\");
        }
        [TestMethod]
        public void CopyTest()
        {
            if (System.IO.File.Exists("C:\\Users\\Public\\test2.txt"))
                System.IO.File.Delete("C:\\Users\\Public\\test2.txt");
            Task task = new Task("cp", "C:\\Users\\Public\\test.txt C:\\Users\\Public\\test2.txt", "1");
            Job job = new Job(task, null);
            Copy.Execute(job, null);
            // Ensure that task is marked complete
            Assert.IsTrue(task.status == "complete");
            // Ensure the file exists
            Assert.IsTrue(System.IO.File.Exists("C:\\Users\\Public\\test2.txt"));
            System.IO.File.Delete("C:\\Users\\Public\\test2.txt");
        } 
        [TestMethod]
        public void CopyTestInvalid()
        {
            if (System.IO.File.Exists("C:\\Users\\Public\\test3.txt"))
                System.IO.File.Delete("C:\\Users\\Public\\test3.txt");
            Task task = new Task("cp", "C:\\asdfasdfathethiethzscgvnbzxg.aste C:\\Users\\Public\\test3.txt", "1");
            Job job = new Job(task, null);
            Copy.Execute(job, null);
            // Ensure that task is marked complete
            Assert.IsTrue(task.status == "error");
        }
        [TestMethod]
        public void DirListTest()
        {
            Task task = new Task("ls", "C:\\", "1");
            Job job = new Job(task, null);
            DirectoryList.Execute(job, null);
            Console.WriteLine(task.message.GetType());
            // Ensure that task is marked complete
            Assert.IsTrue(task.status == "complete");
            // Ensure we have the right type of output in the task message
            Assert.AreEqual(true, (task.message is List<Apfell.Structs.FileInformation>));
        }
        [TestMethod]
        public void DirListTestInvalid()
        {
            Task task = new Task("ls", "C:\\ethetrhehtet", "1");
            Job job = new Job(task, null);
            DirectoryList.Execute(job, null);
            Console.WriteLine(task.message.GetType());
            // Ensure that task is marked complete
            Assert.IsTrue(task.status == "error");
        }
        // Not sure how to test download properly because it requires agent connectivity
        // Also not going to test exit here
        // TODO: Figure out how to test Jobs
        [TestMethod]
        public void KillTest()
        {
            int procId = System.Diagnostics.Process.Start("notepad.exe").Id;
            System.Diagnostics.Process proc = System.Diagnostics.Process.GetProcessById(procId);
            Assert.IsTrue(!proc.HasExited);
            Task task = new Task("kill", $"{procId}", "1");
            Job job = new Job(task, null);
            Kill.Execute(job, null);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "complete");
            // Make sure the process is dead
            Assert.IsTrue(proc.HasExited);
        }
        [TestMethod]
        public void KillTestInvalid()
        {
            Task task = new Task("kill", "1111111111", "1");
            Job job = new Job(task, null);
            Kill.Execute(job, null);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "error");
        }
        [TestMethod]
        public void PowerShellTest()
        {
            string command = "Get-Process -Name explorer";
            Task task = new Task("powershell", command, "1");
            Job job = new Job(task, null);
            PowerShellManager.Execute(job, new Agent(default));
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "complete");
            // Check to make sure we have expected output
            Assert.AreEqual(true, (task.message.ToString().Contains("ProcessName")));
        }
        [TestMethod]
        public void PowerShellTestInvalid()
        {
            string command = "Get-AFDSADSHETHWET";
            Task task = new Task("powershell", command, "1");
            Job job = new Job(task, null);
            PowerShellManager.Execute(job, new Agent(default));
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "complete");
            // Check to make sure we have expected output
            Assert.AreEqual(true, (task.message.ToString().Contains("ERROR")));
        }
        [TestMethod]
        public void PwdTest()
        {
            Task task = new Task("pwd", null, "1");
            Job job = new Job(task, null);
            PrintWorkingDirectory.Execute(job, null);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "complete");
            // Check to make sure output contains C:\
            Assert.AreEqual(true, (task.message.ToString().Contains("C:\\")));
        }
        [TestMethod]
        public void ProcessTest()
        {
            Agent agent = new Agent(default);
            Task task = new Task("run", "whoami /priv", "1");
            Job job = new Job(task, agent);
            Apollo.Tasks.Process.Execute(job, agent);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "complete");
            // Check to see if output contains PRIVILEGES
            Assert.AreEqual(true, (task.message.ToString().Contains("Process executed")));
        }
        [TestMethod]
        public void ProcessTestInvalid()
        {
            Agent agent = new Agent(default);
            Task task = new Task("run", "blah /asdf", "1");
            Job job = new Job(task, agent);
            Apollo.Tasks.Process.Execute(job, agent);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "error");
        }
        [TestMethod]
        public void ProcessListTest()
        {
            Task task = new Task("ps", null, "1");
            Job job = new Job(task, null);
            Apollo.Tasks.ProcessList.Execute(job, null);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "complete");
            // Ensure we have the correct type of output
            Assert.IsTrue(task.message is List<Apfell.Structs.ProcessEntry>);
        }
        [TestMethod]
        public void RemoveTest()
        {
            System.IO.File.Copy("C:\\Users\\Public\\test.txt", "C:\\Users\\Public\\asdfasdf.txt");
            Task task = new Task("rm", "C:\\Users\\Public\\asdfasdf.txt", "1");
            Job job = new Job(task, null);
            Apollo.Tasks.Remove.Execute(job, null);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "complete");
            // Ensure we have the correct type of output
            Assert.IsFalse(System.IO.File.Exists("C:\\Users\\Public\\asdfasdf.txt"));
        }
        [TestMethod]
        public void StealTokenTest()
        {
            Agent agent = new Agent(default);
            Task task = new Task("steal_token", null, "1");
            Job job = new Job(task, agent);
            Token.Execute(job, agent);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "complete");
            // Ensure the agent has a stolen token handle
            Assert.IsTrue(agent.HasAlternateToken());
            Token.stolenHandle = IntPtr.Zero;
        } 
        [TestMethod]
        public void StealTokenTestInvalid()
        {
            Agent agent = new Agent(default);
            Task task = new Task("steal_token", "1351251251", "1");
            Job job = new Job(task, agent);
            Token.Execute(job, agent);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "error");
            // Ensure the agent does not have a stolen token handle
            Assert.IsFalse(agent.HasAlternateToken());
        }
        [TestMethod]
        public void RevertTokenTest()
        {
            Agent agent = new Agent(default);
            Task task = new Task("steal_token", null, "1");
            Job job = new Job(task, agent);
            Token.Execute(job, agent);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "complete");
            // Ensure the agent has a stolen token handle
            Assert.IsTrue(agent.HasAlternateToken());

            task = new Task("rev2self", null, "1");
            job = new Job(task, agent);
            Token.Execute(job, agent);
            // Ensure the task is marked as complete
            Assert.IsTrue(task.status == "complete");
            // Ensure the agent does not have a stolen token handle
            Assert.IsFalse(agent.HasAlternateToken());
        } 
    }
}
