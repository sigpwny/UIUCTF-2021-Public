# Basic Solution

You must download all the wav files first (**order matters** so keep track of the order from the playlist).
Next, if you open it up in audacity you should notice there are three channels instead of two. If you mute one of the tracks you should notice that some interference is happening. If you compare to the original or just try muting in various combinations/look at the waveform closely, you notice that the first track is still the original but the other channels are modified. Since its related to interference you have to overlay the two channels and check where all the interference is happening. If there is audio playing still than its a 1 otherwise its a 0. Note that if you do this process with the cover over another channel it might be flipped bits so you will have to unflip them. If you string them all together it should read out the flag once converted to ascii.

The script I used to overlay the two channels is:
```python
from pydub import AudioSegment
from pydub.playback import play

myAudioFile = "./Ambulo x Kasper Lindmark – Pleasant_track_1.wav"
cover = AudioSegment.from_file(myAudioFile, format="wav")

# Solution
stereo = cover.split_to_mono()
solution = stereo[1].pan(0).overlay(stereo[2].pan(0))
print("Exporting Solution (w/ cover)")
solution.export("./lofi_encryption/solution/Ambulo x Kasper Lindmark – Pleasant_track_1_solved_flag_part_1.wav", format="wav")
```