using System;
using System.IO;
using System.Linq;
using System.Drawing.Imaging;
using System.Drawing;
using System.Windows.Forms;
using System.Runtime.InteropServices;

// Partially sourced from https://www.c-sharpcorner.com/UploadFile/2d2d83/how-to-capture-a-screen-using-C-Sharp/
namespace Screenshot
{
    public class Program
    {
        [DllImport("user32.dll")]
        public static extern bool SetProcessDPIAware();

        public static int Main(string[] args)
        {
            if (args.Length > 0 && (args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help" || args[0] == "-?"))
            {
                Usage();
                return 0;
            }

            string outfile = null;
            if (args.Contains("-o"))
            {
                try
                {
                    outfile = args[Array.FindIndex(args, x => x.Contains("-o")) + 1]; // next item after the -o
                }
                catch
                {
                    Console.WriteLine("[!] Error: no output file specified");
                    return 0;
                }
            }

            SetProcessDPIAware();
            if(Directory.Exists(outfile))
            {
                outfile += "Capture.jpg";
            }
            if(outfile != null && !(outfile.EndsWith(".png") || outfile.EndsWith(".jpg")))
            {
                outfile += ".jpg";
            }
            return Capture(outfile);
        }
        private static void Usage()
        {
            Console.WriteLine("Screenshot.exe - Save screenshots to a file or base64 output");
            Console.WriteLine("Usage: Screenshot.exe [-o <screenshot.jpg>]");
        }
        private static byte[] ImageToByte(Image img)
        {
            ImageConverter converter = new ImageConverter();
            return (byte[])converter.ConvertTo(img, typeof(byte[]));
        }
        public static int Capture(string outfile)
        {
            Rectangle captureRectangle = Screen.AllScreens[0].Bounds;

            Bitmap captureBitmap = new Bitmap(captureRectangle.Size.Width, captureRectangle.Size.Height, PixelFormat.Format32bppArgb);

            //Creating a New Graphics Object
            Graphics captureGraphics = Graphics.FromImage(captureBitmap);
            //Copying Image from The Screen
            captureGraphics.CopyFromScreen(captureRectangle.Left, captureRectangle.Top, 0, 0, captureRectangle.Size);

            if (outfile != null)
            {
                try
                {
                    captureBitmap.Save(outfile, ImageFormat.Jpeg);
                    Console.WriteLine("Image saved to " + outfile);
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error: Could not save image to path: " + outfile);
                    Console.WriteLine(e.ToString());
                }
                return 0;
            }
            else
            {
                byte[] imageBytes = ImageToByte(captureBitmap);
                Console.WriteLine(Convert.ToBase64String(imageBytes));
                return 2; // returnType screenshot
            }
        }
    }
}

