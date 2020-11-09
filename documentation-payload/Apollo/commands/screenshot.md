+++
title = "screenshot"
chapter = false
weight = 103
hidden = false
+++

## Summary
Take a screenshot of the current desktop.

## Usage
```
screenshot
```

## Detailed Summary
The `screenshot` command uses the `System.Drawing.Bitmap` method to create an image of the current desktop and a combination of `System.Drawing.Graphics.FromImage` and `System.Drawing.Imaging.ImageFormat.Jpeg` methods to format the screenshots as valid JPEG files to send back to the Mythic server.
