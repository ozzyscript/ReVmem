
import re 
import sys
import os 
import subprocess
from pathlib import Path
import shutil

# ------------ Helpers -------------

def check_tool_installitaion() -> bool:
    ARCH = "sudo pacman -S gdb"
    DEBIAN = "sudo apt install gdb"
    FEDORA = "sudo dnf install gdb"
    print("Checking if >gcore< is installed...")
    if shutil.which("gcore") is None:
        print("[X] gcore not installed.")
        print(f"You can install it on:")
        print(f"Arch: {ARCH}\nDebian: {DEBIAN}\nFedora: {FEDORA}")
        return False
    return True


def Display_processes(ps_list):
    print()
    if not ps_list:
        print("No processes available.")
        return []

    for i, ps_name in enumerate(ps_list):

        print(f"No[{i}] => ID[{ps_name}] ", end=" ")
        if (i +1) % 3 == 0 :
            print("\n")
                  
    
    print(f"\n{"---" * 20}")

def to_mb(size_bytes: int) -> float:
    return size_bytes / (1024 * 1024)


def to_bytes(size_mb: float) -> int:
   return int(size_mb * 1024 * 1024)


def extract_filename(path):
    for word in path.split("/"):
        if "." in word:
            new_name = word.replace(".","_")
            return new_name

def validate_prgm_name(prgm_name):
    """Helper function get program name from the user, validate it 
        then return the valid name.
        return error message if invalid input.
    """
    if len(prgm_name) > 3:
        return prgm_name
    else:
        return "Invalid Programm name"

def welcome_message():
    print("""
# ============================== ReVmem ============================== #
ReVmem — Runtime Memory Extraction & Analysis Tool

What it does:
  - Attaches to a running process
  - Dumps its memory using gcore
  - Extracts readable strings from RAM

It can be used for:
  - Reverse engineering
  - Memory forensic
  - Low-level runtime analysis

Note:
  - Root privileges may be required
  - Memory dumps can contain secrets (keys, passwords, tokens)

Use responsibly.
Enter the target program name to continue.
# =================================================================== #
""")


PRJ_PATH = Path(__file__).parent.absolute()

def get_process(prgm_name) -> list:

    try:
        psid_list = []
        ps = subprocess.run(["ps", "aux"], capture_output=True, text=True)
        # split long str into separated lines 
        lines = ps.stdout.splitlines()
        for line in lines:
            if prgm_name in line:
                parts = line.split()
                pid = parts[1]
                psid_list.append(pid)
        
        if not psid_list:
            print(f"No process found for: {prgm_name}")

        return psid_list

    except subprocess.CalledProcessError as e:
        print(f"Error getting the process: {e.stderr}")
        return []
    except Exception as e:
        print(f"Error: something went wrong \n {e}")
        return []




def choose_process(ps_list):
    
    if not ps_list:
        print("No processes available.")
        return []
    
    Display_processes(ps_list)

    try: 
        
        choose_ps = int(input("enter the ps number: "))
        if 0 <= choose_ps < len(ps_list):
       #if(cho_ps >= 0) and (cho_ps > len(ps_list)) 
            # print(ps_list[choose_ps])
            return ps_list[choose_ps] 

        else:
            print("Invalid value.")
            return []

    except ValueError:
        print("Invalid value. Try with the correct value")
        return []
    except KeyboardInterrupt:
        print("Operation Canceled.")
        return []
    except Exception as e:
        print(f"Error occurred: {e} ")
        return []




def create_dump_file(psid , prgm_name):

    try:
        # path = Path(__file__).parent.absolute()
        file_name = f"{prgm_name}.{psid}"
        full_path = f"{PRJ_PATH}/{file_name}"

        cmd = ["gcore", "-o", prgm_name, str(psid)]
        
        print("Creating the core file...")
        
        subprocess.run(cmd,capture_output=True, check=True)

        print(f"[DONE] Core file saved at: {full_path}")
        return full_path

    except subprocess.CalledProcessError as e:
        if "not permitted" in str(e.stderr).lower():
            print("Permission Denied. Try running with SUDO")
            sys.exit(126)
    except Exception as e:
        print(f"Error while creating the dump file. Reason: {e}")
        sys.exit(126) 



def save_str_text(output_path,coneten_to_write):
    try:
        with open(output_path, 'a') as output:
            output.write(coneten_to_write) 
            print(f"Data saved at {output_path}")
    except Exception as e:
        print(f"Error when saving Data to file.\nReason:{e}")


def read_dump_file(input_path,output_path,chunk_size=100,min_length=8,size_to_read=None):

    # read all ascii chars and length should be at least min_length 
    pattern_t = fr"[ -~]{{{min_length},}}".encode()

    # total read bytes counter 
    size_read = 0

    # to carry what's left over from the first chunk #so you can get the full text 
    tail = b''

    # read the full file size if size wasn't provided 
    if size_to_read is None: 
        size_to_read = os.path.getsize(input_path) 
        print(f"File size ===> {to_mb(size_to_read):.2f} MB") # for debugging 

    # max bytes to read if the file size too large 
    max_bytes = to_bytes(size_to_read) 

    # temp to count how many words extracted from the ram 
    words_counter = 0
    
    # store extracted strings temporarily to avoid excessive I/O
    words_to_write = []

    with open(input_path, 'rb') as file:

        while size_read < max_bytes: # stop when reach max size
            # temp update the counter 
            words_counter += 1
            
            # print(file.read()) # to see the file content
            # chunk of data to read each time (in bytes) 
            chunk_of_data = file.read(to_bytes(chunk_size))
            
            if not chunk_of_data:

                print("No more data to analyze.")
                break

            # Update the total read size 
            size_read += len(chunk_of_data) 
            print(f"{to_mb(size_read):.2f} MB Analyzed") # for debugging

            # combine the last part of the chunk 
            # with the first part of the new chunk 
            combine = tail + chunk_of_data

            # run regex to extract text 
            strings_found = re.findall(pattern_t, combine) 
            #print(strings_found)
            
            # loop through the text and convert it to human readable text
            for s in strings_found: 
                content = s.decode('ascii',errors='ignore') + "\n" 
                words_to_write.append(content)
                #     print(f"({words_counter}) => >>{content}<<") # for debugging
            if words_to_write:
                save_str_text(output_path,"".join(words_to_write))
                words_to_write.clear()




# =================================================================== #

def main():
   
    if not check_tool_installitaion():
        sys.exit(1)
    
    welcome_message()
    prgm_name = input("Program name >> ")
    valid_program_name = validate_prgm_name(prgm_name)

    ps_list = get_process(valid_program_name)
    if not ps_list:
        sys.exit(1)

    psid = choose_process(ps_list)
    if not psid:
        sys.exit(1)

    dump_file_path = create_dump_file(psid,prgm_name)
    filename = extract_filename(dump_file_path)
    output_path = f"{PRJ_PATH}/{filename}.txt"
    read_dump_file(dump_file_path,output_path)

if __name__ == "__main__":
    main()


