import os
import subprocess

def list_scripts(directory):
    """List all Python scripts in the given directory"""
    scripts = [f for f in os.listdir(directory) if f.endswith('.py') and f != 'main_meny.py']
    return scripts

def open_script_in_new_terminal(script_name, platform):
    """Open the specified script in a new terminal"""
    try:
        if platform == 'linux':
            subprocess.Popen(['gnome-terminal', '--', 'python3', script_name])
        elif platform == 'windows':
            subprocess.Popen(['start', 'cmd', '/k', 'python', script_name], shell=True)
        else:
            print(f"Unknown platform: {platform}")
    except Exception as e:
        print(f"Something went wrong trying to start {script_name}: {e}")

def main():
    """Main"""
    platform = ""
    while platform not in ['linux', 'windows']:
        platform = input("Aru you using linux or windows? (write 'linux' or 'windows'): ").lower()

    directory = '.'
    while True:
        print("Choose what you want to do:")
        scripts = list_scripts(directory)
        for i, script in enumerate(scripts):
            print(f"{i + 1}. {script}")
        print("0. Quit")  
        try:
            choice = int(input("\nChoose a script (number): "))
            if choice == 0:
                print("Quiting...")
                break
            elif 1 <= choice <= len(scripts):
                selected_script = scripts[choice - 1]
                open_script_in_new_terminal(selected_script, platform)
            else:
                print("Invalid value, try again.")
        except ValueError:
            print("Invalid input, try again.")

if __name__ == '__main__':
    main()
