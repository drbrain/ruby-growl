require 'digest'
require 'openssl'
require 'time'
require 'uri'
require 'uri/x_growl_resource'
require 'uuid'

class Growl::GNTP

  class Error < RuntimeError; end

  class ResponseError < Error
    attr_reader :headers

    def initialize message, headers
      super message

      @headers = headers
    end
  end

  class AlreadyProcessed       < ResponseError; end
  class InternalServerError    < ResponseError; end
  class InvalidRequest         < ResponseError; end
  class NetworkFailure         < ResponseError; end
  class NotAuthorized          < ResponseError; end
  class NotificationDisabled   < ResponseError; end
  class RequiredHeaderMissing  < ResponseError; end
  class TimedOut               < ResponseError; end
  class UnknownApplication     < ResponseError; end
  class UnknownNotification    < ResponseError; end
  class UnknownProtocol        < ResponseError; end
  class UnknownProtocolVersion < ResponseError; end

  ERROR_MAP = {
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

  ENCRYPTION_ALGORITHMS = {
    'DES'  => 'DES-CBC',
    '3DES' => 'DES-EDE3-CBC',
    'AES'  => 'AES-192-CBC',
  }

  attr_accessor :encrypt
  attr_accessor :uuid # :nodoc:
  attr_reader :notifications
  attr_accessor :password

  def initialize host, application, notifications
    @host = host
    @application = application
    @notifications = notifications
    @uuid = UUID.new

    @encrypt = 'NONE'
    @password = nil
  end

  def cipher key
    algorithm = ENCRYPTION_ALGORITHMS[@encrypt]

    raise Error, "unknown GNTP encryption mode #{@encrypt}" unless algorithm

    cipher = OpenSSL::Cipher.new algorithm
    cipher.encrypt

    cipher.key = key
    iv = cipher.random_iv

    return cipher, iv
  end

  def connect
    TCPSocket.new @host, 23053
  end

  def key_hash algorithm
    key  = @password.dup.force_encoding Encoding::BINARY
    salt = self.salt
    basis = "#{key}#{salt}"

    key = algorithm.digest basis

    hash = algorithm.hexdigest key

    return key, hash, salt
  end

  def notify(notification, title, text = nil, priority = 0, sticky = false,
             callback_url = nil, &block)

    raise ArgumentError, 'provide either a url or a block for callbacks, ' \
                         'not both' if block and callback_url

    callback = callback_url || block_given?

    packet = packet_notify(notification, title, text,
                           priority, sticky, callback)

    send packet, &block
  end

  def packet type, headers
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
      packet << body
    else
      encipher, iv = cipher key

      encrypt_info = "#{@encrypt}:#{Digest.hexencode iv}"

      packet << "GNTP/1.0 #{type} #{encrypt_info} #{key_info}"

      encrypted = encipher.update(body)
      encrypted << encipher.final

      packet << encrypted
    end

    packet << nil
    packet << nil

    packet.join "\r\n"
  end

  def packet_notify notification, title, text, priority, sticky, callback
    raise ArgumentError, "invalid priority level #{priority}" unless
      priority >= -2 and priority <= 2

    headers = []
    headers << "Notification-ID: #{@uuid.generate}"
    headers << "Notification-Name: #{notification}"
    headers << "Notification-Title: #{title}"
    headers << "Notification-Text: #{text}"         if text
    headers << "Notification-Priority: #{priority}" if priority.nonzero?
    headers << "Notification-Sticky: True"          if sticky
    if callback then
      headers << "Notification-Callback-Context: context"
      headers << "Notification-Callback-Context-Type: type"
      headers << "Notification-Callback-Target: #{callback}" unless
        callback == true
    end

    packet :NOTIFY, headers
  end

  def packet_register
    headers = []
    headers << "Notifications-Count: #{@notifications.length}"
    headers << nil
    @notifications.each do |notification|
      headers << "Notification-Name: #{notification}"
      headers << "Notification-Enabled: true"
    end

    packet :REGISTER, headers
  end

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

  def receive packet
    $stderr.puts "> #{packet.gsub(/\r\n/, "\n> ")}" if $DEBUG

    packet = packet.strip.split "\r\n"

    info = packet.shift
    info =~ %r%^GNTP/([\d.]+) (\S+) (\S+)$%

    version = $1
    message = $2
    encryption = $3

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

  def register
    send packet_register
  end

  def salt
    OpenSSL::Random.random_bytes 16
  end

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

