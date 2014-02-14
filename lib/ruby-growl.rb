require 'digest/md5'
require 'socket'

begin
  require 'dnssd'
rescue LoadError
end

##
# ruby-growl allows you to perform Growl notifications from machines without
# growl installed (for example, non-OSX machines).
#
# In version 4, the Growl class is a wrapper for Growl::UDP and Growl::GNTP.
# The GNTP protocol allows setting icons for notifications and callbacks.  To
# upgrade from version 3 replace the notification names passed to initialize
# with a call to #add_notification.
#
# Basic usage:
#
#   require 'ruby-growl'
#
#   g = Growl.new "localhost", "ruby-growl"
#   g.add_notification "ruby-growl Notification"
#   g.notify "ruby-growl Notification", "It came from ruby-growl!",
#            "Greetings!"
#
# For GNTP users, ruby-growl ships with the Ruby icon from the {Ruby Visual
# Identity Team}[http://rubyidentity.org/]:
#
#   require 'ruby-growl'
#   require 'ruby-growl/ruby_logo'
#
#   g = Growl.new "localhost", "ruby-growl"
#   g.add_notification("notification", "ruby-growl Notification",
#                      Growl::RUBY_LOGO_PNG)
#   g.notify "notification", "It came from ruby-growl", "Greetings!"
#
# See Growl::UDP and Growl::GNTP for protocol-specific API.

class Growl

  ##
  # ruby-growl version

  VERSION = '4.1'

  ##
  # Growl error base class

  class Error < RuntimeError
  end

  ##
  # Password for authenticating and encrypting requests.

  attr_accessor :password

  ##
  # List of hosts accessible via dnssd

  def self.list type
    raise 'you must gem install dnssd' unless Object.const_defined? :DNSSD

    require 'timeout'

    growls = []

    begin
      Timeout.timeout 10 do
        DNSSD.browse! type do |reply|
          next unless reply.flags.add?

          growls << reply

          break unless reply.flags.more_coming?
        end
      end
    rescue Timeout::Error
    end

    hosts = []

    growls.each do |growl|
      DNSSD.resolve! growl do |reply|
        hosts << reply.target
        break
      end
    end

    hosts.uniq
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

    g = new options[:host], options[:name]
    g.add_notification notify_type, options[:name], options[:icon]
    g.password = options[:password]

    g.notify(notify_type, options[:title], message, options[:priority],
             options[:sticky])
  end

  ##
  # Parses argv-style options from +ARGV+ into an options hash

  def self.process_args argv
    require 'optparse'

    options = {
      host:        nil,
      icon:        nil,
      list:        false,
      message:     nil,
      name:        "ruby-growl",
      notify_type: "ruby-growl Notification",
      password:    nil,
      priority:    0,
      sticky:      false,
      title:       "",
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

      o.on("-i", "--icon [ICON]", "Icon url") do |val|
        options[:icon] = URI(val)
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
        puts 'Growl GNTP hosts:'
        puts list '_gntp._tcp'
        puts
        puts 'Growl UDP hosts:'
        puts list '_growl._tcp'
      rescue => e
        raise unless e.message =~ /gem install dnssd/

        abort "#{e.message} to use --list"
      end
      return
    end

    notify options
  end

  ##
  # Creates a new growl basic notifier for +host+ and +application_name+.
  #
  # +growl_type+ is used to specify the type of growl server to connect to.
  # The following values are allowed:
  #
  # nil::
  #   Automatically determine the growl type.  If a GNTP server is not found
  #   then ruby-growl chooses UDP.
  # 'GNTP'::
  #   Use GNTP connections.  GNTP is supported by Growl 1.3 and newer and by
  #   Growl for Windows.
  # 'UDP'::
  #   Uses the UDP growl protocol.  UDP growl is supported by Growl 1.2 and
  #   older.
  #
  # You can use <tt>growl --list</tt> to see growl servers on your local
  # network.

  def initialize host, application_name, growl_type = nil
    @host = host
    @application_name = application_name

    @notifications = {}
    @password      = nil

    @growl_type = choose_implementation growl_type
  end

  ##
  # Adds a notification named +name+ to the basic notifier.  For GNTP servers
  # you may specify a +display_name+ and +icon+ and set the default +enabled+
  # status.

  def add_notification name, display_name = nil, icon = nil, enabled = true
    @notifications[name] = display_name, icon, enabled
  end

  def choose_implementation type # :nodoc:
    raise ArgumentError,
          "type must be \"GNTP\", \"UDP\" or nil; was #{type.inspect}" unless
      ['GNTP', 'UDP', nil].include? type

    return type if type

    TCPSocket.open @host, Growl::GNTP::PORT do end

    'GNTP'
  rescue SystemCallError
    'UDP'
  end

  ##
  # Sends a notification of type +name+ with the given +title+, +message+,
  # +priority+ and +sticky+ settings.

  def notify name, title, message, priority = 0, sticky = false, icon = nil
    case @growl_type
    when 'GNTP' then
      notify_gntp name, title, message, priority, sticky, icon
    when 'UDP'  then
      notify_udp name, title, message, priority, sticky
    else
      raise Growl::Error, "bug, unknown growl type #{@growl_type.inspect}"
    end

    self
  end

  def notify_gntp name, title, message, priority, sticky, icon = nil # :nodoc:
    growl = Growl::GNTP.new @host, @application_name
    growl.password = @password

    @notifications.each do |notification_name, details|
      growl.add_notification notification_name, *details
    end

    growl.register

    growl.notify name, title, message, priority, sticky
  end

  def notify_udp name, title, message, priority, sticky # :nodoc:
    all_notifications = @notifications.keys
    default_notifications =
      @notifications.select do |notification_name, (_, _, enabled)|
        enabled
      end.map do |notification_name,|
        notification_name
      end

    growl = Growl::UDP.new(@host, @application_name, all_notifications,
                           default_notifications, @password)

    growl.notify name, title, message, priority, sticky
  end

end

require 'ruby-growl/gntp'
require 'ruby-growl/udp'

