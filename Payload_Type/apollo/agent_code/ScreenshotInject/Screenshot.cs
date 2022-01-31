using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;


namespace ScreenshotInject
{
    public static class Screenshot
    {
        public static byte[][] GetScreenshots()
        {
            List<byte[]> bshots = new List<byte[]>();

            foreach(Screen sc in Screen.AllScreens)
            {
                byte[] bSCreen = GetBytesFromScreen(sc);
                bshots.Add(bSCreen);
            }
            return bshots.ToArray();
        }

        private static byte[] GetBytesFromScreen(Screen screen)
        {
            byte[] bScreen = null;
            using (Bitmap bmpScreenCapture = new Bitmap(screen.Bounds.Width,
                                            screen.Bounds.Height))
            {
                using (Graphics g = Graphics.FromImage(bmpScreenCapture))
                {
                    g.CopyFromScreen(screen.Bounds.X,
                                        screen.Bounds.Y,
                                        0, 0,
                                        bmpScreenCapture.Size,
                                        CopyPixelOperation.SourceCopy);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        bmpScreenCapture.Save(ms, System.Drawing.Imaging.ImageFormat.Jpeg);
                        bScreen = ms.ToArray();
                    }
                }
            }

            return bScreen;
        }
    }
}
