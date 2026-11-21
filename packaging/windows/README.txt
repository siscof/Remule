Remule for Windows
==================

Remule is a file-sharing program for the eD2k and Kad networks, the ones
eMule and aMule use. It is an early version: it works, but expect rough
edges.

Starting it
-----------
1. Unzip the whole folder somewhere, for example in your Documents. Keep the
   files together: Remule.exe needs remuled.exe and remule-gui.exe beside it.
2. Double-click Remule.exe.

   Windows may warn that the program is from an unknown publisher (it is not
   signed). Click "More info", then "Run anyway".
   Windows Firewall may ask whether remuled may use the network: allow it,
   or you will not be able to download.

The window opens after a few seconds. It connects to a server and to Kad by
itself; the Networks page shows how it is doing.

Using it
--------
- Searches: type what you are looking for, choose the network, and search.
  Double-click a result to download it.
- You can also paste an ed2k:// link or a magnet link with an eD2k hash.
- Transfers shows your downloads; you can pause, resume or cancel them.
- Finished files go to:
      %APPDATA%\remule\daemon\Incoming
  (paste that into the Explorer address bar). They are shared with others
  from there.

Closing the window stops Remule and saves everything: downloads continue
where they left off next time.

Good to know
------------
- "LowID" on the Networks page means other people cannot connect to you
  directly, because your router does not let them in. Downloads still work,
  but more slowly. To get a "HighID", forward TCP port 4662 and UDP port
  4672 on your router to this PC.
- Everything Remule keeps is in %APPDATA%\remule. To start over, close
  Remule and delete that folder.
- Remule does not use or change an aMule or eMule installation.

Remule is free software under the GNU General Public License, version 2 or
later (see LICENSE.md). Its source code is at:
    https://github.com/siscof/Remule
