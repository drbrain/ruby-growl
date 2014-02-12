= ruby-growl

home :: https://github.com/drbrain/ruby-growl
bugs :: https://github.com/drbrain/ruby-growl/issues
rdoc :: http://docs.seattlerb.org/ruby-growl

== DESCRIPTION:

A pure-ruby growl notifier for UDP and GNTP growl protocols.  ruby-growl
allows you to perform Growl notifications from machines without growl
installed (for example, non-OSX machines).

What is growl?  Growl is a really cool "global notification system originally
for Mac OS X".

You can receive Growl notifications on various platforms and send them from
any machine that runs Ruby.

OS X: http://growl.info
Windows: http://www.growlforwindows.com/gfw/
Linux: http://github.com/mattn/growl-for-linux

ruby-growl also contains a command-line notification tool named 'growl'.  It
is almost completely option-compatible with growlnotify.  (All except for -p
is supported, use --priority instead.)

== FEATURES/PROBLEMS:

* Requires "Listen for incoming notifications" enabled on the growl server

== INSTALL:

  gem install ruby-growl

== LICENSE:

Copyright Eric Hodel.  All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. Neither the names of the authors nor the names of their contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

