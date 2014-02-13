require 'digest'
require 'net/http'
require 'openssl'
require 'time'
require 'uri'
require 'uri/x_growl_resource'
require 'uuid'

##
# Growl Notification Transport Protocol 1.0
#
# In growl 1.3, GNTP replaced the UDP growl protocol from earlier versions.
# GNTP has some new features beyond those supported in earlier versions
# including:
#
# * Callback support
# * Notification icons
# * Encrypted notifications (not supported by growl at this time)
#
# Notably, subscription support is not implemented.
#
# This implementation is based on information from
# http://www.growlforwindows.com/gfw/help/gntp.aspx

class Growl::GNTP

  ##
  # Growl GNTP port

  PORT = 23053

  ##
  # Base GNTP error class

  class Error < Growl::Error; end

  ##
  # Raised when the server indicates a GNTP response error

  class ResponseError < Error

    ##
    # The headers from the error response

    attr_reader :headers

    ##
    # Creates a new error with +message+ from the response Error-Description
    # header and the full +headers+

    def initialize message, headers
      super message

      @headers = headers
    end

  end

  ##
  # Raised when the original request was already received by this server

  class AlreadyProcessed       < ResponseError; end

  ##
  # Raised when the server has an internal error

  class InternalServerError    < ResponseError; end

  ##
  # Raised when the request was malformed

  class InvalidRequest         < ResponseError; end

  ##
  # Raised when the server was unavailable or the client could not reach the
  # server

  class NetworkFailure         < ResponseError; end

  ##
  # Raised when the request supplied a missing or wrong password or was
  # otherwise not authorized

  class NotAuthorized          < ResponseError; end

  ##
  # Raised when the given notification type was registered but disabled

  class NotificationDisabled   < ResponseError; end

  ##
  # Raised when the request is missing a required header

  class RequiredHeaderMissing  < ResponseError; end

  ##
  # Raised when the server timed out waiting for the request to complete

  class TimedOut               < ResponseError; end

  ##
  # Raised when the application is not registered to send notifications

  class UnknownApplication     < ResponseError; end

  ##
  # Raised when the notification type was not registered

  class UnknownNotification    < ResponseError; end

  ##
  # Raised when the request given was not a GNTP request

  class UnknownProtocol        < ResponseError; end

  ##
  # Raised when the request used an unknown GNTP protocol version

  class UnknownProtocolVersion < ResponseError; end

  ERROR_MAP = { # :nodoc:
    200 => Growl::GNTP::TimedOut,
    201 => Growl::GNTP::NetworkFailure,
    300 => Growl::GNTP::InvalidRequest,
    301 => Growl::GNTP::UnknownProtocol,
    302 => Growl::GNTP::UnknownProtocolVersion,
    303 => Growl::GNTP::RequiredHeaderMissing,
    400 => Growl::GNTP::NotAuthorized,
    401 => Growl::GNTP::UnknownApplication,
    402 => Growl::GNTP::UnknownNotification,
    403 => Growl::GNTP::AlreadyProcessed,
    404 => Growl::GNTP::NotificationDisabled,
    500 => Growl::GNTP::InternalServerError,
  }

  ENCRYPTION_ALGORITHMS = { # :nodoc:
    'DES'  => 'DES-CBC',
    '3DES' => 'DES-EDE3-CBC',
    'AES'  => 'AES-192-CBC',
  }

  ##
  # Enables encryption for request bodies.
  #
  # Note that this does not appear to be supported in a released version of
  # growl.

  attr_accessor :encrypt

  ##
  # Sets the application icon
  #
  # The icon may be any image NSImage supports

  attr_accessor :icon

  ##
  # Objects used to generate UUIDs

  attr_accessor :uuid # :nodoc:

  ##
  # Hash of notifications registered with the server

  attr_reader :notifications

  ##
  # Password for authenticating and encrypting requests.  If this is set,
  # authentication automatically takes place.

  attr_accessor :password

  ##
  # Creates a new Growl::GNTP instance that will communicate with +host+ and
  # has the given +application+ name, and will send the given
  # +notification_names+.
  #
  # If you wish to set icons or display names for notifications, use
  # add_notification instead of sending +notification_names+.

  def initialize host, application, notification_names = nil
    @host          = host
    @application   = application
    @notifications = {}
    @uuid          = UUID.new

    notification_names.each do |name|
      add_notification name
    end if notification_names

    @encrypt  = 'NONE'
    @password = nil
    @icon     = nil
  end

  ##
  # Adds a notification with +name+ (internal) and +display_name+ (shown to
  # user).  The +icon+ map be an image (anything NSImage supports) or a URI
  # (which is unsupported in growl 1.3).  If the notification is +enabled+ it
  # will be displayed by default.

  def add_notification name, display_name = nil, icon = nil, enabled = true
    @notifications[name] = display_name, icon, enabled
  end

  ##
  # Creates a symmetric encryption cipher for +key+ based on the #encrypt
  # method.

  def cipher key, iv = nil
    algorithm = ENCRYPTION_ALGORITHMS[@encrypt]

    raise Error, "unknown GNTP encryption mode #{@encrypt}" unless algorithm

    cipher = OpenSSL::Cipher.new algorithm
    cipher.encrypt

    cipher.key = key

    if iv then
      cipher.iv = iv
    else
      iv = cipher.random_iv
    end

    return cipher, iv
  end

  ##
  # Creates a TCP connection to the chosen #host

  def connect
    TCPSocket.new @host, PORT
  end

  ##
  # Returns an encryption key, authentication hash and random salt for the
  # given hash +algorithm+.

  def key_hash algorithm
    key  = @password.dup.force_encoding Encoding::BINARY
    salt = self.salt
    basis = "#{key}#{salt}"

    key = algorithm.digest basis

    hash = algorithm.hexdigest key

    return key, hash, salt
  end

  ##
  # Sends a +notification+ with the given +title+ and +text+.  The +priority+
  # may be between -2 (lowest) and 2 (highest).  +sticky+ will indicate the
  # notification must be manually dismissed.  +callback_url+ is supposed to
  # open the given URL on the server's web browser when clicked, but I haven't
  # seen this work.
  #
  # If a block is given, it is called when the notification is clicked, times
  # out, or is manually dismissed.

  def notify(notification, title, text = nil, priority = 0, sticky = false,
             coalesce_id = nil, callback_url = nil, &block)

    raise ArgumentError, 'provide either a url or a block for callbacks, ' \
                         'not both' if block and callback_url

    callback = callback_url || block_given?

    packet = packet_notify(notification, title, text,
                           priority, sticky, coalesce_id, callback)

    send packet, &block
  end

  ##
  # Creates a +type+ packet (such as REGISTER or NOTIFY) with the given
  # +headers+ and +resources+.  Handles authentication and encryption of the
  # packet.

  def packet type, headers, resources = {}
    packet = []

    body = []
    body << "Application-Name: #{@application}"
    body << "Origin-Software-Name: ruby-growl"
    body << "Origin-Software-Version: #{Growl::VERSION}"
    body << "Origin-Platform-Name: ruby"
    body << "Origin-Platform-Version: #{RUBY_VERSION}"
    body << "Connection: close"
    body.concat headers
    body << nil
    body = body.join "\r\n"

    if @password then
      digest = Digest::SHA512
      key, hash, salt = key_hash digest
      key_info = "SHA512:#{hash}.#{Digest.hexencode salt}"
    end

    if @encrypt == 'NONE' then
      packet << ["GNTP/1.0", type, "NONE", key_info].compact.join(' ')
      packet << body.force_encoding("ASCII-8BIT")
    else
      encipher, iv = cipher key

      encrypt_info = "#{@encrypt}:#{Digest.hexencode iv}"

      packet << "GNTP/1.0 #{type} #{encrypt_info} #{key_info}"

      encrypted = encipher.update body
      encrypted << encipher.final

      packet << encrypted
    end

    resources.each do |id, data|
      if iv then
        encipher, = cipher key, iv

        encrypted = encipher.update data
        encrypted << encipher.final

        data = encrypted
      end

      packet << "Identifier: #{id}"
      packet << "Length: #{data.length}"
      packet << nil
      packet << data
      packet << nil
    end

    packet << nil
    packet << nil

    packet.join "\r\n"
  end

  ##
  # Creates a notify packet.  See #notify for parameter details.

  def packet_notify(notification, title, text, priority, sticky, coalesce_id,
                    callback)
    raise ArgumentError, "invalid priority level #{priority}" unless
      priority >= -2 and priority <= 2

    resources = {}
    _, icon, = @notifications[notification]

    if URI === icon then
      icon_uri = icon
    elsif icon then
      id = @uuid.generate

      resources[id] = icon
    end

    headers = []
    headers << "Notification-ID: #{@uuid.generate}"
    headers << "Notification-Coalescing-ID: #{coalesce_id}" if coalesce_id
    headers << "Notification-Name: #{notification}"
    headers << "Notification-Title: #{title}"
    headers << "Notification-Text: #{text}"         if text
    headers << "Notification-Priority: #{priority}" if priority.nonzero?
    headers << "Notification-Sticky: True"          if sticky
    headers << "Notification-Icon: #{icon}"         if icon_uri
    headers << "Notification-Icon: x-growl-resource://#{id}" if id

    if callback then
      headers << "Notification-Callback-Context: context"
      headers << "Notification-Callback-Context-Type: type"
      headers << "Notification-Callback-Target: #{callback}" unless
        callback == true
    end

    packet :NOTIFY, headers, resources
  end

  ##
  # Creates a registration packet

  def packet_register
    resources = {}

    headers = []

    case @icon
    when URI then
      headers << "Application-Icon: #{@icon}"
    when NilClass then
      # ignore
    else
      app_icon_id = @uuid.generate

      headers << "Application-Icon: x-growl-resource://#{app_icon_id}"

      resources[app_icon_id] = @icon
    end

    headers << "Notifications-Count: #{@notifications.length}"
    headers << nil

    @notifications.each do |name, (display_name, icon, enabled)|
      headers << "Notification-Name: #{name}"
      headers << "Notification-Display-Name: #{display_name}" if display_name
      headers << "Notification-Enabled: true"                 if enabled

      # This does not appear to be used by growl so ruby-growl sends the
      # icon with every notification.
      if URI === icon then
        headers << "Notification-Icon: #{icon}"
      elsif icon then
        id = @uuid.generate

        headers << "Notification-Icon: x-growl-resource://#{id}"

        resources[id] = icon
      end

      headers << nil
    end

    headers.pop # remove trailing nil

    packet :REGISTER, headers, resources
  end

  ##
  # Parses the +value+ for +header+ into the correct ruby type

  def parse_header header, value
    return [header, nil] if value == '(null)'

    case header
    when 'Notification-Enabled',
         'Notification-Sticky' then
      if value =~ /^(true|yes)$/i then
        [header, true]
      elsif value =~ /^(false|no)$/i then
        [header, false]
      else
        [header, value]
      end
    when 'Notification-Callback-Timestamp' then
      [header, Time.parse(value)]
    when 'Error-Code',
         'Notifications-Count',
         'Notifications-Priority',
         'Subscriber-Port',
         'Subscription-TTL' then
      [header, value.to_i]
    when 'Application-Name',
         'Error-Description',
         'Notification-Callback-Context',
         'Notification-Callback-Context-Type',
         'Notification-Callback-Target',
         'Notification-Coalescing-ID',
         'Notification-Display-Name',
         'Notification-ID',
         'Notification-Name',
         'Notification-Text',
         'Notification-Title',
         'Origin-Machine-Name',
         'Origin-Platform-Name',
         'Origin-Platform-Version',
         'Origin-Software-Version',
         'Origin-Sofware-Name',
         'Subscriber-ID',
         'Subscriber-Name' then
      value.force_encoding Encoding::UTF_8

      [header, value]
    when 'Application-Icon',
         'Notification-Icon' then
      value = URI value
      [header, value]
    else
      [header, value]
    end
  end

  ##
  # Receives and handles the response +packet+ from the server and either
  # raises an error or returns a headers Hash.

  def receive packet
    $stderr.puts "> #{packet.gsub(/\r\n/, "\n> ")}" if $DEBUG

    packet = packet.strip.split "\r\n"

    info = packet.shift
    info =~ %r%^GNTP/([\d.]+) (\S+) (\S+)$%

    version = $1
    message = $2

    raise Error, "invalid info line #{info.inspect}" unless version

    headers = packet.flat_map do |header|
      key, value = header.split ': ', 2

      parse_header key, value
    end

    headers = Hash[*headers]

    return headers if %w[-OK -CALLBACK].include? message

    error_code = headers['Error-Code']
    error_class = ERROR_MAP[error_code]
    error_message = headers['Error-Description']

    raise error_class.new(error_message, headers)
  end

  ##
  # Sends a registration packet based on the given notifications

  def register
    send packet_register
  end

  ##
  # Creates a random salt for use in authentication and encryption

  def salt
    OpenSSL::Random.random_bytes 16
  end

  ##
  # Sends +packet+ to the server and yields a callback, if given

  def send packet
    socket = connect

    $stderr.puts "< #{packet.gsub(/\r\n/, "\n< ")}" if $DEBUG

    socket.write packet

    result = receive socket.gets "\r\n\r\n\r\n"

    if block_given? then
      callback = receive socket.gets "\r\n\r\n\r\n"

      yield callback
    end

    result
  end

end

