from pydub import AudioSegment
from pydub.playback import play
import argparse
import ntpath
import os

def debug_mode():
    # Debug Mode Stuff
    debug = False
    debug_mode = input("Do you want to enter debug mode? 1 = yes and 0 = no: ")
    if (debug_mode == "1"):
        print("Debug Mode On!")
        debug = True
    else:
        print("Debug Mode Off!")
    return debug

def setup(filename, flag):
    #Load an audio file
    print("Running Setup...")
    # myAudioFile = "./WYS – Snowman.wav"
    myAudioFile = filename
    print("Loading in {}".format(myAudioFile))
    cover = AudioSegment.from_file(myAudioFile, format="wav")
    # make the cover mono
    cover = cover.set_channels(1)

    # Get Message
    # message = "uiuctf{interfered}"
    message = flag
    message_binary = ''.join(format(ord(i), '08b') for i in message)
    print("Your message is: {}\nYour message in binary: {}".format(message, message_binary))
    print("Length of message in binary is: {}".format(len(message_binary)))
    
    # Get cover statistics
    cover_duration = cover.duration_seconds
    cover_seg_dur = cover_duration / (len(message_binary))
    cover_seg_dur_ms = int(cover_seg_dur * 1000)
    cover_dur_ms = cover_duration * 1000
    print("Duration of a segment: {}s".format(cover_seg_dur))
    print("Duration of a rounded segment: {}s".format(int(cover_duration)))
    print("Duration of a rounded segment in ms: {}ms".format(cover_seg_dur_ms))
    
    # make sure cover has a size that is an integer
    cover = cover[0:int(cover.duration_seconds * 1000)]

    print("Finished Setup!")
    return cover, message_binary, cover_dur_ms, cover_seg_dur_ms

def share_1(cover, message_binary, cover_dur_ms, cover_seg_dur_ms):
    print("Calculating Share 1...")

    # Debug Mode
    debug = debug_mode()

    share1_array = []
    count = 0
    i = 0
    while i < cover_dur_ms:
        if i < cover_seg_dur_ms * (len(message_binary) - 1):
            if debug:
                print("Binary Data Value: {}".format(message_binary[count]))
            
            if message_binary[count] == '0':
                if debug:
                    print("Waveform segment remains the same.")
                share1_array.append(cover[i:i+cover_seg_dur_ms])
            else:
                if debug:
                    print("Waveform segment is inverted")
                share1_array.append(cover[i:i+cover_seg_dur_ms].invert_phase())
            i += cover_seg_dur_ms
            count += 1
            if debug:
                print("Current Segment Start Time: {}s".format(i / 1000))
                print("Current Segment End Time: {}s".format((i + cover_seg_dur_ms) / 1000))
        else:
            if debug:
                print("Last Data Value:")
                print("Binary Data Value: {}".format(message_binary[count]))

            if message_binary[count] == '0':
                if debug:
                    print("Waveform segment remains the same.")
                share1_array.append(cover[cover_seg_dur_ms * (len(message_binary) - 1):int(cover_dur_ms)])
            else:
                if debug:
                    print("Waveform segment is inverted")
                share1_array.append(cover[cover_seg_dur_ms * (len(message_binary) - 1):int(cover_dur_ms)].invert_phase())
            break
    
    if debug:
        print("Number of segments: {}".format(len(share1_array)))
    
    share1 = share1_array[0]
    
    if debug:
        print("Share 1 First Segment Duration: {}".format(share1.duration_seconds))
        print("Share 1 Last Segment Duration: {}".format(share1_array[len(share1_array) - 1].duration_seconds))
    
    # Combine all segments into one track
    for x in range(1,len(share1_array)):
            share1 += share1_array[x]
    
    print("Share 1 Calculation Completed!")
    if debug:
        print("Exiting Debug Mode...")
    return share1

def share_2(s1, message_binary, cover_dur_ms, cover_seg_dur_ms):
    print("Calculating Share 2...")

    # Debug Mode
    debug = debug_mode()
    
    share2_array = []
    count = 0
    i = 0
    
    while i < cover_dur_ms:
        if i < cover_seg_dur_ms * (len(message_binary) - 1):
            if debug:
                print("Binary Data Value: {}".format(message_binary[count]))

            if message_binary[count] == '1':
                if debug:
                    print("Waveform segment remains the same.")
                share2_array.append(s1[i:i+cover_seg_dur_ms])
            else:
                if debug:
                    print("Waveform segment is inverted")
                share2_array.append(s1[i:i+cover_seg_dur_ms].invert_phase())
            i += cover_seg_dur_ms
            count += 1
            if debug:
                print("Current Segment Start Time: {}s".format(i / 1000))
                print("Current Segment End Time: {}s".format((i + cover_seg_dur_ms) / 1000))
        else:
            if debug:
                print("Last Data Value:")
                print("Binary Data Value: {}".format(message_binary[count]))

            if message_binary[count] == '1':
                if debug:
                    print("Waveform segment remains the same.")
                share2_array.append(s1[cover_seg_dur_ms * (len(message_binary) - 1):int(cover_dur_ms)])
            else:
                if debug:
                    print("Waveform segment is inverted")
                share2_array.append(s1[cover_seg_dur_ms * (len(message_binary) - 1):int(cover_dur_ms)].invert_phase())
            break

    if debug:
        print("Number of segments: {}".format(len(share2_array)))

    share2 = share2_array[0]

    if debug:
        print("Share 2 First Segment Duration: {}".format(share2.duration_seconds))
        print("Share 2 Last Segment Duration: {}".format(share2_array[len(share2_array) - 1].duration_seconds))

    for x in range(1,len(share2_array)):
            share2 += share2_array[x]
    
    print("Share 2 Calculation Completed!")
    if debug:
        print("Exiting Debug Mode...")

    return share2

def generate_audio_files(filename, flag, directory, iteration):
    filename_clean = ntpath.basename(filename).split(".")[0]
    rel_path_f = "./" + directory + "/" + filename_clean
    rel_path = "./" + directory
    if not os.path.isdir(rel_path_f):
        os.makedirs(rel_path_f)
    if not os.path.isdir(rel_path_f + "/audio_parts"):
        os.mkdir(rel_path_f + "/audio_parts")
    if not os.path.isdir(rel_path_f + "/solution"):
        os.mkdir(rel_path_f + "/solution")
    if not os.path.isdir(rel_path + "/encrypted_audio"):
        os.mkdir(rel_path + "/encrypted_audio")
    if not os.path.isdir(rel_path + "/solution"):
        os.mkdir(rel_path + "/solution")
    # Get relevant data (do some parsing) 
    cover, message_binary, cover_dur_ms, cover_seg_dur_ms = setup(filename, flag)

    # Calculate Share 1 (Keep the same if 0 and invert phase if 1)
    s1 = share_1(cover, message_binary, cover_dur_ms, cover_seg_dur_ms)
    s1 = s1.set_channels(1)
    print("Cover Duration == Share 1 Duration: {} == {}\n".format(cover.duration_seconds,s1.duration_seconds))
    
    # Calculate Share 2 (Keep the same if 1 and invert phase if 0 but on Share 1)
    s2 = share_2(s1, message_binary, cover_dur_ms, cover_seg_dur_ms)
    s2 = s2.set_channels(1)
    print("Cover Duration == Share 2 Duration: {} == {}\n".format(cover.duration_seconds,s2.duration_seconds))

    # Create Stereo combination of the two shares
    combine_shares = AudioSegment.from_mono_audiosegments(s1, s2)
    
    # Export cover and shares
    # print("Exporting Cover Audio")
    # cover.export("./{}/{}/audio_parts/cover.wav".format(directory, filename_clean), format="wav")
    # print("Exporting Share 1 Audio")
    # s1.export("./{}/{}/audio_parts/share1.wav".format(directory, filename_clean), format="wav")
    # print("Exporting Share 2 Audio")
    # s2.export("./{}/{}/audio_parts/share2.wav".format(directory, filename_clean), format="wav")
    # print("Exporting Encrypted Audio (no cover)")
    # combine_shares.export("./{}/{}/audio_parts/encrypted.wav".format(directory, filename_clean), format="wav")

    # Overlay Cover over encryption and see if method still works
    # s1_overlay = s1.overlay(cover)
    # s2_overlay = s2.overlay(cover)
    # combine_shares_w_overlay = AudioSegment.from_mono_audiosegments(s1_overlay, s2_overlay)
    s1 = s1
    s2 = s2
    combine_shares_w_overlay = AudioSegment.from_mono_audiosegments(cover, s1, s2)

    # Export Cover Overlay Version
    print("Exporting Encrypted Audio (w/ cover)")
    combine_shares_w_overlay.export("./{}/encrypted_audio/{}_track_{}.wav".format(directory, filename_clean, iteration + 1), format="wav")

    # Solution
    # stereo = combine_shares.split_to_mono()
    # solution = stereo[0].pan(0).overlay(stereo[1].pan(0))
    # print("Exporting Solution (no cover)")
    # solution.export("./{}/{}/solution/solved_no_cover.wav".format(directory, filename_clean), format="wav")

    # Solution Overlay
    stereo = combine_shares_w_overlay.split_to_mono()
    solution = stereo[1].pan(0).overlay(stereo[2].pan(0))
    print("Exporting Solution (w/ cover)")
    solution.export("./{}/solution/{}_solved_flag_part_{}.wav".format(directory, filename_clean, iteration + 1), format="wav")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f","--flag", help="CTF Flag to be encoded", required=True)
    parser.add_argument("-l","--list", nargs='+', help="All Audio Files to be used", required=True)
    parser.add_argument("-o","--output", help="Directory to store results relative to current location")
    args = parser.parse_args()

    # process values
    if args.flag:
        flag = args.flag

    if args.list:
        files = args.list

    out_dir = "audio_file_results"
    if args.output:
        out_dir = args.output
    
    num_files = len(files)
    if (num_files > len(flag)):
        raise ValueError("Flag not long enough for number of files")

    if num_files > 1:
        n = int(len(flag)/num_files)
        flag_sub = [flag[i:i+n] for i in range(0, len(flag), n)]
        if (len(flag_sub) > num_files):
            end_string = ""
            # r_flag_sub = reversed(flag_sub)
            for i in range(len(flag_sub) - 1, num_files - 2, -1):
                print(i)
                print(flag_sub[i])
                if len(flag_sub[i]) > 1:
                    end_string += flag_sub[i][::-1]
                else:
                    end_string += flag_sub[i]
                flag_sub.pop()
            flag_sub.append(end_string[::-1])

    else:
        flag_sub = [flag]
    
    # print(files)
    # print(flag)
    # print(flag_sub)
    # print(len(flag_sub) - num_files)
    # print(out_dir)

    for x in range(0, len(files)):
        generate_audio_files(files[x], flag_sub[x], out_dir, x)

if __name__ == "__main__":
    # execute only if run as a script
    main()