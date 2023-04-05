using System;
using AudioSwitcher.AudioApi.CoreAudio;

namespace Program
{
    public class Program
    {
        public static void Main(string[] args)
        {
            //by default, the URL is a no-ad version of Rick Astley's magnum opus.  
            string url = "https://www.youtube.com/watch?v=a3Z7zEc7AXQ?autoplay=1"; //"?autoplay=1" at the end of the url should make the video play automatically even if the user has autoplay turned off.
            //
            string volumeLevel = "100"

            if (args.Length > 0)
            {
                if (args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help" || args[0] == "-help")
                {
                    Usage();
                    return;
                }

                if (args.Length == 1)
                {
                    url = args[0];
                }
            }
            OpenUrl(url);
            //turn the volume to the user's specified level (default 100)
            VolumeSwitch(volumeLevel);

        }
        static void Usage()
        {
            Console.WriteLine("Rickrolls the client by default, or open any URL specified");
            Console.WriteLine("usage: Rickroll <url>");
        }
        static void OpenUrl(string url)
        {
            try
            {
                //launch the URL in the default browser
                System.Diagnostics.Process.Start(url);

            }
            catch (System.ComponentModel.Win32Exception noBrowser)
            {
                if (noBrowser.ErrorCode == -2147467259)
                    Console.WriteLine(noBrowser.Message);
            }
            catch (System.Exception other)
            {
                Console.WriteLine(other.Message);
            }
        }
        static void VolumeSwitch(volumeLevel) {
            CoreAudioDevice defaultPlaybackDevice = new CoreAudioController().DefaultPlaybackDevice;
            Debug.WriteLine("Current Volume:" + defaultPlaybackDevice.Volume);
            defaultPlaybackDevice.Volume = volumeLevel;
        }

    }
}
