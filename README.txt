NullWord – Installation and Usage Guide

--------------------------------------

Purpose

  NullWord is a stateless password generator for Linux desktops.

  If you enter the same master password and service name, you’ll always get the same password --- regardless of what computer you're on.  

  This means you only need to memorise one password.
  
  You're also not depending on an external server or centralized password repository, making the system trustless.

  Note that NullWord uses the Argon2id password hashing algorithm with prohibitively slow settings. This should help it remain secure well into the future. Unfortunately, this also means that on a typical computer from 2025, it takes a bit under half a second to generate your password. This is by design: the cost to attackers increases as computers get faster, but for you it's still fast enough.

--------------------------------------

Supported Linux Distributions

  Fedora-based: Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux, and similar.
  Debian-based: Ubuntu, Linux Mint, Pop!_OS, and similar.
  Other: Arch Linux, OpenSUSE, etc. (see your distribution's software installation instructions)

--------------------------------------

Installing On Fedora

1. Install required software:

  Open a terminal and run the following command:

    sudo dnf install gcc make argon2-devel xclip

  If you would like an alternative clipboard tool instead of xclip, replace xclip with xsel in the above command.

  If your desktop is running Wayland (used in modern GNOME or KDE), also run:

    sudo dnf install wl-clipboard

2. Download NullWord:

  Go to the NullWord project page or repository and download the source code archive (for example, NullWord.zip or NullWord.tar.gz).

  If you have a direct link, you can use wget or curl in the terminal. For example:

    wget https://example.com/NullWord.tar.gz

  Or download using your web browser and move the archive to your home folder.

3. Decompress the archive:

  If the file ends with .zip, run:

    unzip NullWord.zip

  If the file ends with .tar.gz, run:

    tar xvf NullWord.tar.gz

  This will create a folder containing the files nullword.c and Makefile.

4. Build and install NullWord:

  Install NullWord for all users with:

    sudo make install

  Now you can run NullWord from any terminal window by typing:

    nullword

--------------------------------------

Installing On Debian

1. Install required software:

  Open a terminal and run these commands, one at a time:

    sudo apt update

    sudo apt install build-essential libargon2-dev xclip

  If your desktop is running Wayland, also run:

    sudo apt install wl-clipboard

  If you want an alternative clipboard tool, you can run:

    sudo apt install xsel

2. Download NullWord:

  Go to the NullWord project page or repository and download the source code archive (for example, NullWord.zip or NullWord.tar.gz).

  If you have a direct link, you can use wget or curl in the terminal. For example:

    wget https://example.com/NullWord.tar.gz

  Or download using your web browser and move the archive to your home folder.

3. Decompress the archive:

  If the file ends with .zip, run:

    unzip NullWord.zip

  If the file ends with .tar.gz, run:

    tar xvf NullWord.tar.gz

  This will create a folder containing the files nullword.c and Makefile.

4. Build and install NullWord:

  Install NullWord for all users with:

    sudo make install

  Now you can run NullWord from any terminal window by typing:

    NullWord

--------------------------------------

WARNINGS!

NullWord does not store your passwords. If you forget your master password, your passwords cannot be recovered.

Your "salt" and "pepper" (first and last name, which can be fake, but must always be the same for you) are stored in plaintext in ~/.NullWord/creds.txt, and are used as part of the hashing process to ensure your passwords are unique to you.

IMPORTANT: Please choose a high-entropy master password with at least 24 characters to keep yourself safe.

--------------------------------------

Advice for Choosing a Master Password

One way to make a strong master password is to use the Truncated Poem Trick:

  1. Make up a two-line poem. Use unusual words, or even words that you invent.

  2. Discard punctuation, and break up words that consist of prefixes, suffixes, or subwords.

  3. For each word in your poem, take the first half of the word, rounded down. (If the word is made up, use the whole word).

  4. Join the pieces together to form your master password.

  5. Ensure final password is about 24 characters long.

  6. If it's longer, just take first letters of short or common words, until it's about 24 long.

Example:

  Poem:

    stardust drifts while bloofers gleam
    under midnight’s twoobik dream

  Conversion:

    stardust   -> star dust  -> stdu
    drifts     -> dri        -> dri
    while      -> wh         -> wh
    bloofers   -> bloofers   -> bloofers
    gleam      -> gl         -> gl
    under      -> un         -> un
    midnight’s -> mid nights -> mnig
    twoobik    -> twoobik    -> twoobik
    dream      -> dr         -> dr

  Password:
  
    stdudriwhbloofersglunmnigtwoobikdr
  
  This example password is 34 characters:
  
    Too long --- typing this repeatedly will become annoying!

  Shorter poem (omitting while):

    stardust drifts, bloofers gleam
    under midnight’s twoobiks dream

  Reducing words to their first letter as needed

    stardust   -> star dust  -> stdu
    drifts     -> d          -> d
    bloofers   -> bloofers   -> bloofers
    gleam      -> g          -> g
    under      -> u          -> u
    midnight’s -> midnights  -> m
    twoobiks   -> twoobiks   -> twoobiks
    dream      -> d          -> d

  Password:
  
    stdudbloofersgumtwoobiksd

  This example password is 24 characters:

    Perfect!

--------------------------------------

How To Use NullWord

1. Open a terminal and run NullWord:

    NullWord

   (Or run ./NullWord from the folder if you did not install system-wide)

2. Enter the name of the service when prompted (for example: amazon)

3. Enter your master password when prompted (it will be hidden as you type)

4. If your computer has xclip, xsel, or wl-copy installed, the password will be copied to your clipboard so you can paste it. If not, the password will not be shown for security; see troubleshooting.

--------------------------------------

Troubleshooting

If clipboard copy is not working:

  - Check that you have at least one of xclip, xsel, or wl-clipboard installed.

  - Make sure you are running in a graphical environment (not over SSH or in text-only mode).

  - You can test clipboard copy by running:

      echo test | xclip -selection clipboard

    Then open a text editor and press Ctrl+V to paste. If you see the word "test", your clipboard is working.

If you see "Permission denied" when running NullWord after install, set the permissions so all users can run it:

    sudo chmod 755 /usr/local/bin/NullWord

If you see an Argon2 error, try closing other programs to free up memory. If you continue to see errors, NullWord probably isn't a good fit for your system. Note that, in principle, you can lower the Argon2 memory settings in the source code - BUT, this is strongly discouraged, because if you lose the custom parameters, you'll be unable to recover your passwords.

If you enter "logout" as the service name, your salt/pepper credentials will be deleted and you'll be prompted to set them up again next time.

--------------------------------------

Security Reminders

  - Never lose your master password—no one can recover it for you.

  - Do not use your NullWord master password anywhere else.

  - It's OK to write your password and/or poem on paper while you memorise it. But be sure to dispose of the paper effectively. For example: tear into parts, put different parts in different bins in different suburbs at different times, etc.

  - It's probably better not to modify the parameters inside nullword.c. If you lose your custom parameters, you'll lose access to your passwords. The defaults are fine, just use those.
  
  - If you ever do need to change parameters in nullword.c (NOT RECOMMENDED!), write them down and keep them with your backup.

  - Passwords are never stored on your block storage devices (SSD, HD, etc.)—each one is generated only when you ask for it, and lives only in memory. To maximize the benefits of this, consider enabling "swap with session-based encryption" (Google it).

  - NullWord is best kept separate from other, potentially compromised software you might be running. Consider using a hypervisor-based operating system like QubesOS if security matters to you.

--------------------------------------

Stay safe, and stay in control!
