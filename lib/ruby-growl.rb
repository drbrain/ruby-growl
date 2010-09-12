#!/usr/local/bin/ruby -w

require 'digest/md5'
require 'socket'

##
# ruby-growl allows you to perform Growl notification via UDP from machines
# without growl installed (for example, non-OSX machines).
#
# What's Growl?  Growl is a really cool "global notification system for Mac OS
# X".  See http://growl.info/
#
# You'll need a Mac to recieve Growl notifications, but you can send Growl
# notifications from any UDP-capable machine that runs Ruby.
#
# See also the Ruby Growl bindings in Growl's subversion repository:
# http://growl.info/documentation/growl-source-install.php
#
# ruby-growl also contains a command-line notification tool named 'growl'.  It
# is almost completely option-compatible with growlnotify.  (All except for -p
# is supported, use --priority instead.)
#
# = Synopsis
#
#   g = Growl.new "127.0.0.1", "ruby-growl",
#                 ["ruby-growl Notification"]
#   g.notify "ruby-growl Notification", "It Came From Ruby-Growl",
#            "Greetings!"

class Growl

  ##
  # The Ruby that ships with Tiger has a broken #pack, so 'v' means network
  # byte order instead of 'n'.

  BROKEN_PACK = [1].pack("n") != "\000\001" # :nodoc:

  little_endian = [1].pack('V*') == [1].pack('L*')
  little_endian = !little_endian if BROKEN_PACK

  ##
  # Endianness of this machine

  LITTLE_ENDIAN = little_endian

  ##
  # ruby-growl Version

  VERSION = '3.0'

  ##
  # Growl Network Registration Packet +pack+ Format
  #--
  # Format:
  #
  #   struct GrowlNetworkRegistration {
  #     struct GrowlNetworkPacket {
  #       unsigned char version;
  #       unsigned char type;
  #     } __attribute__((packed));
  #     unsigned short appNameLen;
  #     unsigned char numAllNotifications;
  #     unsigned char numDefaultNotifications;
  #     /*
  #      *  Variable sized. Format:
  #      *  <application name><all notifications><default notifications><checksum>
  #      *  where <all notifications> is of the form (<length><name>){num} and
  #      *  <default notifications> is an array of indices into the all notifications
  #      *  array, each index being 8 bits.
  #      */
  #     unsigned char data[];
  #   } __attribute__((packed));

  GNR_FORMAT = "CCnCCa*"

  GNR_FORMAT.gsub!(/n/, 'v') if BROKEN_PACK

  ##
  # Growl Network Notification Packet +pack+ Format
  #--
  # Format:
  #
  #   struct GrowlNetworkNotification {
  #     struct GrowlNetworkPacket {
  #       unsigned char version;
  #       unsigned char type;
  #     } __attribute__((packed));
  #     struct GrowlNetworkNotificationFlags {
  #       unsigned reserved: 12;
  #       signed   priority: 3;
  #       unsigned sticky:   1;
  #     } __attribute__((packed)) flags; //size = 16 (12 + 3 + 1)
  #     unsigned short nameLen;
  #     unsigned short titleLen;
  #     unsigned short descriptionLen;
  #     unsigned short appNameLen;
  #     /*
  #      *  Variable sized. Format:
  #      *  <notification name><title><description><application name><checksum>
  #      */
  #     unsigned char data[];
  #   } __attribute__((packed));

  GNN_FORMAT = "CCnnnnna*"

  GNN_FORMAT.gsub!(/n/, 'v') if BROKEN_PACK

  # For litle endian machines the NetworkNotificationFlags aren't in network
  # byte order

  GNN_FORMAT.sub!((BROKEN_PACK ? 'v' : 'n'), 'v') if LITTLE_ENDIAN

  ##
  # Growl UDP Port

  GROWL_UDP_PORT = 9887

  ##
  # Growl Protocol Version

  GROWL_PROTOCOL_VERSION = 1

  ##
  # Growl Registration Packet Id

  GROWL_TYPE_REGISTRATION = 0

  ##
  # Growl Notification Packet Id

  GROWL_TYPE_NOTIFICATION = 1

  ##
  # List of hosts accessible via dnssd

  def self.list
    require 'dnssd'

    growls = []

    DNSSD.browse! '_growl._tcp' do |reply|
      next unless reply.flags.add?

      growls << reply

      break unless reply.flags.more_coming?
    end

    hosts = []

    growls.each do |growl|
      DNSSD.resolve! growl do |reply|
        hosts << reply.target
        break
      end
    end

    hosts.uniq
  rescue LoadError
    raise 'you must gem install dnssd'
  end

  ##
  # Sends a notification using +options+

  def self.notify options
    message = options[:message]

    unless message then
      puts "Type your message and hit ^D" if $stdin.tty?
      message = $stdin.read
    end

    notify_type = options[:notify_type]
    notify_types = [notify_type]

    g = new(options[:host], options[:name], notify_types, notify_types,
            options[:password])

    g.notify(notify_type, options[:title], message, options[:priority],
             options[:sticky])
  end

  ##
  # Parses argv-style options from +ARGV+ into an options hash

  def self.process_args argv
    require 'optparse'

    options = {
      :host        => nil,
      :message     => nil,
      :name        => "ruby-growl",
      :notify_type => "ruby-growl Notification",
      :password    => nil,
      :priority    => 0,
      :sticky      => false,
      :title       => "",
      :list        => false,
    }

    opts = OptionParser.new do |o|
      o.program_name = File.basename $0
      o.version = Growl::VERSION
      o.release = nil

      o.banner = <<-BANNER
Usage: #{o.program_name} -H HOSTNAME [options]

  Where possible, growl is compatible with growlnotify's arguments.
  (Except for -p, use --priority)

Synopsis:
  echo \"message\" | growl -H localhost

  growl -H localhost -m message

      BANNER

      o.separator "Options:"

      o.on("-H", "--host HOSTNAME", "Send notifications to HOSTNAME") do |val|
        options[:host] = val
      end

      o.on("-n", "--name [NAME]", "Sending application name",
              "(Defaults to \"ruby-growl\")") do |val|
        options[:name] = val
      end

      o.on("-y", "--type [TYPE]", "Notification type",
              "(Defauts to \"Ruby Growl Notification\")") do |val|
        options[:notify_type] = val
      end

      o.on("-t", "--title [TITLE]", "Notification title") do |val|
        options[:title] = val
      end

      o.on("-m", "--message [MESSAGE]",
           "Send this message instead of reading STDIN") do |val|
        options[:message] = val
      end

      # HACK -p -1 raises
      o.on("--priority [PRIORITY]", Integer,
           "Notification priority",
           "Priority can be between -2 and 2") do |val|
        options[:priority] = val
      end

      o.on("-s", "--[no-]sticky", "Make the notification sticky") do |val|
        options[:sticky] = val
      end

      o.on("-P", "--password [PASSWORD]", "Growl UDP Password") do |val|
        options[:password] = val
      end

      o.on("--list", "List growl hosts using dnssd") do |val|
        options[:list] = true
      end
    end

    opts.parse! argv

    abort opts.to_s unless options[:host] or options[:list]

    options
  end

  ##
  # Command-line interface

  def self.run argv = ARGV
    options = process_args argv

    if options[:list] then
      begin
        puts list
      rescue => e
        raise unless e.message =~ /gem install dnssd/

        abort "#{e.message} to use --list"
      end
      return
    end

    notify options
  end

  ##
  # Creates a new Growl notifier and automatically registers any notifications
  # with the remote machine.
  #
  # +host+ is the host to contact.
  #
  # +app_name+ is the name of the application sending the notifications.
  #
  # +all_notifies+ is a list of notification types your application sends.
  #
  # +default_notifies+ is a list of notification types that are turned on by
  # default.
  #
  # I'm not sure about what +default_notifies+ is supposed to be set to, since
  # there is a comment that says "not a subset of all_notifies" in the code.
  #
  # +password+ is the password needed to send notifications to +host+.

  def initialize(host, app_name, all_notifies, default_notifies = nil,
                 password = nil)
    @socket = UDPSocket.open
    # FIXME This goes somewhere else
    @socket.connect host, GROWL_UDP_PORT
    @app_name = app_name
    @all_notifies = all_notifies
    @default_notifies = default_notifies.nil? ? all_notifies : default_notifies
    @password = password

    register
  end

  ##
  # Sends a notification.
  #
  # +notify_type+ is the type of notification to send.
  #
  # +title+ is a title for the notification.
  #
  # +message+ is the body of the notification.
  #
  # +priority+ is the priorty of message to send.
  #
  # +sticky+ makes the notification stick until clicked.

  def notify(notify_type, title, message, priority = 0, sticky = false)
    raise "Unknown Notification" unless @all_notifies.include? notify_type
    raise "Invalid Priority" unless priority >= -2 and priority <= 2

    send notification_packet(notify_type, title, message, priority, sticky)
  end

  ##
  # Registers the notification types with +host+.

  def register
    send registration_packet
  end

  ##
  # Sends a Growl packet

  def send(packet)
    set_sndbuf packet.length
    @socket.send packet, 0
    @socket.flush
  end

  ##
  # Builds a Growl registration packet

  def registration_packet
    length = 0
    data = []
    data_format = ""

    packet = [
      GROWL_PROTOCOL_VERSION,
      GROWL_TYPE_REGISTRATION
    ]

    packet << @app_name.bytesize
    packet << @all_notifies.length
    packet << @default_notifies.length

    data << @app_name
    data_format = "a#{@app_name.bytesize}"

    @all_notifies.each do |notify|
      data << notify.length
      data << notify
      data_format << "na#{notify.length}"
    end

    @default_notifies.each do |notify|
      data << @all_notifies.index(notify) if @all_notifies.include? notify
      data_format << "C"
    end

    data_format.gsub!(/n/, 'v') if BROKEN_PACK

    data = data.pack data_format

    packet << data

    packet = packet.pack GNR_FORMAT

    checksum = Digest::MD5.new << packet
    checksum.update @password unless @password.nil?

    packet << checksum.digest

    return packet
  end

  ##
  # Builds a Growl notification packet

  def notification_packet(name, title, description, priority, sticky)
    flags = 0
    data = []

    packet = [
      GROWL_PROTOCOL_VERSION,
      GROWL_TYPE_NOTIFICATION,
    ]

    flags = 0
    flags |= ((0x7 & priority) << 1) # 3 bits for priority
    flags |= 1 if sticky # 1 bit for sticky

    packet << flags
    packet << name.bytesize
    packet << title.length
    packet << description.bytesize
    packet << @app_name.bytesize

    data << name
    data << title
    data << description
    data << @app_name

    packet << data.join
    packet = packet.pack GNN_FORMAT

    checksum = Digest::MD5.new << packet
    checksum.update @password unless @password.nil?

    packet << checksum.digest

    return packet
  end

  ##
  # Set the size of the send buffer
  #--
  # Is this truly necessary?

  def set_sndbuf(length)
    @socket.setsockopt Socket::SOL_SOCKET, Socket::SO_SNDBUF, length
  end

end

