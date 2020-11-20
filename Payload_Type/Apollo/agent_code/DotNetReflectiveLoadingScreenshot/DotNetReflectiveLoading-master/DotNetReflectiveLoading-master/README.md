# DotNetReflectiveLoading

## Purpose

This project is the culmination of playing around with the native application CLR hosting APIs. It provides the ability to
reflectively load and execute code from .NET assemblies, and will be a bit of an exploration of the COM and reflection facilities
underpinning .NET on Windows. 

## Use

At the present time, this project has a few limitations (e.g., it doesn't support constructors that take arguments currently),
up to and including the fact that it only supports reflective loading (as opposed to loading from disk), and is still a bit 
of a work in progress.

It currently contains three class definitions:

ClrDomain - which manages the AppDomain and some hosting facilities
ClrAssembly - which manages an individual loaded assembly
ClrClass - which manages an individual class instance

The following snippet of code will load an assembly:

```cpp

std::vector<uint8_t> vec;

// ... load assembly from file into vec here

clr::ClrDomain dom;

auto asm = dom.load(vec);
if(!asm) {
 std::cout << "Failed to load assembly!" << std::endl;
 return0;
}

```

At this point, the variable asm contains a std::unique_ptr to a clr::ClrAssembly class.

Assuming for a second that we have an assembly that looks like this:

```csharp

namespace TestLib
{
    public class Class1
    {
        private string stuff;
        public Class1()
        {
            stuff = "Herp derp string";
            System.Console.WriteLine("Success");
        }
        public void mb(string text) {
            System.Windows.Forms.MessageBox.Show(text);

        }

        public static void drop_file(string filename, string filecontents)
        {
            FileStream tmp = File.Open(filename, FileMode.Create);
            byte[] buf = Encoding.ASCII.GetBytes(filecontents);
            tmp.Write(buf, 0, buf.Length);
            tmp.Close();
        }
    }
}

```

We can invoke the static method without much work at all, by providing the class name, function name, and arguments:

```cpp

asm->invoke_static(L"TestLib.Class1", L"drop_file", L"stuff.txt", L"Lorem Ipsum");

```

At this point, we should now have a file named "stuff.txt", containing the Lorem Ipsum text. Now,
supposing we want to actually construct an instance of the class, and create a message box:

```cpp

auto cls = asm->construct(L"TestLib.Class1"); // Constructor will get invoked here
if(!cls)
   return 0;
   
cls->invoke_method(L"mb", L"Success!");

```

At this point, the popup should display.
