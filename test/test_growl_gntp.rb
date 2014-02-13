# coding: UTF-8

require 'minitest/autorun'
require 'ruby-growl'
require 'ruby-growl/ruby_logo'
require 'stringio'

class TestGrowlGNTP < Minitest::Test

  class Socket
    attr_reader :_input, :_output

    def initialize *a
      @_input  = StringIO.new
      @_output = StringIO.new
    end

    def gets separator
      @_input.gets separator
    end

    def read *a
      @_input.read(*a)
    end

    def write data
      @_output.write data
    end

    def _input= data
      @_input.write data
      @_input.rewind
    end
  end

  class UUID
    def generate() 4 end
  end

  def setup
    @gntp = Growl::GNTP.new 'localhost', 'test-app'
    @gntp.uuid = UUID.new

    rocket_path = File.join 'test', 'rocketAlpha.jpg'
    rocket_path = File.expand_path rocket_path

    @jpg_data = File.read rocket_path, mode: 'rb'
    @jpg_url  = "file://#{rocket_path}"
  end

  def test_add_notification
    @gntp.add_notification 'test', 'Test Notification', @jpg_url, true

    expected = { 'test' => ['Test Notification', @jpg_url, true] }

    assert_equal expected, @gntp.notifications
  end

  def test_cipher_des
    @gntp.encrypt = 'DES'
    key = "P>\a\x8AB\x01\xDF\xCET\x0F\xC7\xC9\xBC_^\xC0"

    cipher, iv = @gntp.cipher key

    assert_equal 'DES-CBC', cipher.name
    assert_equal 8, cipher.iv_len
    assert_equal 8, cipher.key_len

    assert_kind_of String,  iv

    assert_endecrypt cipher, key, iv
  end

  def test_cipher_iv
    @gntp.encrypt = 'AES'
    input_iv = 'junkjunkjunkjunk'

    key = "\xF8\x93\xD4\xEB)u(\x06" \
          "\x92\x88|)\x00\x97\xC73" \
          "\x16/\xF3o\xB9@\xBA\x9D"

    cipher, iv = @gntp.cipher key, input_iv

    assert_equal 'AES-192-CBC', cipher.name
    assert_equal 24, cipher.key_len

    assert_equal input_iv, iv

    assert_endecrypt cipher, key, iv
  end

  def test_cipher_triple_des
    @gntp.encrypt = '3DES'
    key = "\xF8\x93\xD4\xEB)u(\x06" \
          "\x92\x88|)\x00\x97\xC73" \
          "\x16/\xF3o\xB9@\xBA\x9D"

    cipher, iv = @gntp.cipher key

    assert_equal 'DES-EDE3-CBC', cipher.name
    assert_equal 8, cipher.iv_len
    assert_equal 24, cipher.key_len

    assert_kind_of String, iv

    assert_endecrypt cipher, key, iv
  end

  def test_cipher_aes
    @gntp.encrypt = 'AES'
    key = "\xF8\x93\xD4\xEB)u(\x06" \
          "\x92\x88|)\x00\x97\xC73" \
          "\x16/\xF3o\xB9@\xBA\x9D"

    cipher, iv = @gntp.cipher key

    assert_equal 'AES-192-CBC', cipher.name
    assert_equal 16, cipher.iv_len
    assert_equal 24, cipher.key_len

    assert_kind_of String, iv

    assert_endecrypt cipher, key, iv
  end

  def test_key_hash_md5
    stub_salt
    @gntp.password = 'πassword'
    algorithm = Digest::MD5

    key, hash, = @gntp.key_hash algorithm

    expected = [
       80,  62,   7, 138,  66,   1, 223, 206,
       84,  15, 199, 201, 188,  95,  94, 192,
    ]

    assert_equal expected, key.unpack('C*'), 'key'

    expected = 'c552e68e5d86772487f6014b02cb4a14'

    assert_equal expected, hash, 'hash'
  end

  def test_key_hash_sha1
    stub_salt
    @gntp.password = 'πassword'
    algorithm = Digest::SHA1

    key, hash, = @gntp.key_hash algorithm

    expected = [
      206, 111,  53,  40, 168, 195,   0, 193,
      209,   5, 102, 197, 114, 212, 228,  64,
       38, 168,  23, 187
    ]

    assert_equal expected, key.unpack('C*'), 'key'

    expected = '03247e7e5b3ae9033dba23cf4637023542bc10d3'

    assert_equal expected, hash, 'hash'
  end

  def test_key_hash_sha256
    stub_salt
    @gntp.password = 'πassword'
    algorithm = Digest::SHA256

    key, hash, = @gntp.key_hash algorithm

    expected = [
      248, 147, 212, 235,  41, 117,  40,   6,
      146, 136, 124,  41,   0, 151, 199,  51,
       22,  47, 243, 111, 185,  64, 186, 157,
      227, 141, 213,  37, 127,  20, 155, 130
    ]

    assert_equal expected, key.unpack('C*'), 'key'

    expected = '88b55cd37083d87e' \
               'cf79de12afe1c1b8' \
               '8300c0d84c6ac35b' \
               'cc6227c47a55087f'

    assert_equal expected, hash, 'hash'
  end

  def test_key_hash_sha512
    stub_salt
    @gntp.password = 'πassword'
    algorithm = Digest::SHA512

    key, hash, = @gntp.key_hash algorithm

    expected = [
      134, 105,  63,   2, 240,  31,  36, 158,
       20, 198, 246, 227, 240, 111, 158,   3,
       37,  23,   1, 129,  27, 189,  68, 110,
      105, 213,  90,   0,  23, 146, 218,  69,
      253,   4,  57,   3, 152, 101,  22,  55,
       89,  99, 133,  21,  95, 238, 181,   5,
       67,  87, 108,  15, 128, 190, 137, 150,
      151,  83, 245, 219,  21, 251,  95, 182,
    ]

    assert_equal expected, key.unpack('C*'), 'key'

    expected = '2407322ff8b1f13c' \
               '75774ea8a954c74c' \
               'fb5138813f49a7c5' \
               '5e230cfad7426c42' \
               'cc4771262331a559' \
               '2ddc243462d7f6f8' \
               '9ebd7581cb52c451' \
               '7648834d624c3c60'

    assert_equal expected, hash, 'hash'
  end

  def test_notify
    stub_socket "GNTP/1.0 -OK NONE\r\n" \
                "Response-Action: NOTIFY\r\n" \
                "Notification-ID: (null)\r\n\r\n\r\n"

    response = @gntp.notify 'test', 'title', 'message', 2, true

    expected = {
      'Response-Action' => 'NOTIFY',
      'Notification-ID' => nil,
    }

    assert_equal expected, response
  end

  def test_notify_callback
    callback_result = nil
    stub_socket <<-STREAM
GNTP/1.0 -OK NONE\r
Response-Action: NOTIFY\r
Notification-ID: 4\r
\r
\r
\r
GNTP/1.0 -CALLBACK NONE\r
Response-Action: NOTIFY\r
Notification-ID: 4\r
Notification-Callback-Result: CLICKED\r
Notification-Callback-Timestamp: 2012-03-28\r
Notification-Callback-Context: context\r
Notification-Callback-Context-Type: type\r
Application-Name: test\r
\r
\r
    STREAM

    response = @gntp.notify 'test', 'title', 'message' do |result|
      callback_result = result
    end

    expected = {
      'Response-Action'                    => 'NOTIFY',
      'Notification-ID'                    => '4',
      'Notification-Callback-Result'       => 'CLICKED',
      'Notification-Callback-Timestamp'    => Time.parse('2012-03-28'),
      'Notification-Callback-Context'      => 'context',
      'Notification-Callback-Context-Type' => 'type',
      'Application-Name'                   => 'test'
    }

    assert_equal expected, callback_result

    expected = {
      'Response-Action' => 'NOTIFY',
      'Notification-ID' => '4',
    }

    assert_equal expected, response
  end

  def test_notify_callback_with_uri
    e = assert_raises ArgumentError do
      @gntp.notify 'test', 'title', 'message', 0, false, nil, 'uri' do end
    end

    assert_equal 'provide either a url or a block for callbacks, not both',
                 e.message
  end

  def test_notify_coalesce
    stub_socket "GNTP/1.0 -OK NONE\r\n" \
                "Response-Action: NOTIFY\r\n" \
                "Notification-ID: (null)\r\n\r\n\r\n"

    response = @gntp.notify 'test', 'title', 'message', 0, false, 'some_id'

    expected = {
      'Response-Action' => 'NOTIFY',
      'Notification-ID' => nil,
    }

    assert_equal expected, response
  end

  def test_packet
    expected = <<-EXPECTED
GNTP/1.0 REGISTER NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Foo: bar\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet('REGISTER', ["Foo: bar"])
  end

  def test_packet_encrypt_des
    @gntp.encrypt  = 'DES'
    @gntp.password = 'password'

    packet = @gntp.packet 'REGISTER', ["Foo: bar"]

    info, body = packet.split "\r\n", 2

    _, _, algorithm_info, key_info = info.split ' '

    cipher, iv = algorithm_info.split ':'

    assert_equal 'DES', cipher

    iv = [iv].pack 'H*'

    cipher = OpenSSL::Cipher.new Growl::GNTP::ENCRYPTION_ALGORITHMS[cipher]

    assert_equal 'DES-CBC', cipher.name

    _, salt = key_info.split '.', 2

    salt = [salt].pack 'H*'

    key = Digest::SHA512.digest "password#{salt}"

    body = body.chomp "\r\n\r\n"

    decrypted = decrypt cipher, key, iv, body

    expected = <<-EXPECTED
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Foo: bar\r
    EXPECTED

    assert_equal expected, decrypted
  end

  def test_packet_encrypt_3des
    @gntp.encrypt  = '3DES'
    @gntp.password = 'password'

    packet = @gntp.packet 'REGISTER', ["Foo: bar"]

    info, body = packet.split "\r\n", 2

    _, _, algorithm_info, key_info = info.split ' '

    cipher, iv = algorithm_info.split ':'

    assert_equal '3DES', cipher

    iv = [iv].pack 'H*'

    cipher = OpenSSL::Cipher.new Growl::GNTP::ENCRYPTION_ALGORITHMS[cipher]

    assert_equal 'DES-EDE3-CBC', cipher.name

    _, salt = key_info.split '.', 2

    salt = [salt].pack 'H*'

    key = Digest::SHA512.digest "password#{salt}"

    body = body.chomp "\r\n\r\n"

    decrypted = decrypt cipher, key, iv, body

    expected = <<-EXPECTED
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Foo: bar\r
    EXPECTED

    assert_equal expected, decrypted
  end

  def test_packet_encrypt_aes
    @gntp.encrypt  = 'AES'
    @gntp.password = 'password'

    packet = @gntp.packet 'REGISTER', ["Foo: bar"]

    info, body = packet.split "\r\n", 2

    _, _, algorithm_info, key_info = info.split ' '

    cipher, iv = algorithm_info.split ':'

    assert_equal 'AES', cipher

    iv = [iv].pack 'H*'

    cipher = OpenSSL::Cipher.new Growl::GNTP::ENCRYPTION_ALGORITHMS[cipher]

    assert_equal 'AES-192-CBC', cipher.name

    _, salt = key_info.split '.', 2

    salt = [salt].pack 'H*'

    key = Digest::SHA512.digest "password#{salt}"

    body = body.chomp "\r\n\r\n"

    decrypted = decrypt cipher, key, iv, body

    expected = <<-EXPECTED
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Foo: bar\r
    EXPECTED

    assert_equal expected, decrypted
  end

  def test_packet_encrypt_aes_icon
    @gntp.encrypt  = 'AES'
    @gntp.password = 'password'

    packet = @gntp.packet 'REGISTER', ["Foo: bar"], { 'icon' => @jpg_data }

    info, body = packet.split "\r\n", 2

    _, _, algorithm_info, key_info = info.split ' '

    cipher, iv = algorithm_info.split ':'

    assert_equal 'AES', cipher

    iv = [iv].pack 'H*'

    cipher = OpenSSL::Cipher.new Growl::GNTP::ENCRYPTION_ALGORITHMS[cipher]

    assert_equal 'AES-192-CBC', cipher.name

    _, salt = key_info.split '.', 2

    salt = [salt].pack 'H*'

    key = Digest::SHA512.digest "password#{salt}"

    body = body.chomp "\r\n\r\n"

    end_of_headers = body.index "\r\nIdentifier: "
    headers = body.slice! 0, end_of_headers

    decrypted = decrypt cipher, key, iv, headers

    expected = <<-EXPECTED
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Foo: bar\r
    EXPECTED

    assert_equal expected, decrypted

    body =~ /Length: (\d+)\r\n\r\n/

    data_length = $1.to_i
    data_offset = $`.length + $&.length

    data = body[data_offset, data_length]

    decrypted = decrypt cipher, key, iv, data

    assert_equal @jpg_data, decrypted
  end

  def test_packet_hash
    @gntp.password = 'password'

    packet = @gntp.packet 'REGISTER', ["Foo: bar"]

    info, body = packet.split "\r\n", 2

    _, _, algorithm_info, key_info = info.split ' '

    assert_equal 'NONE', algorithm_info

    key_info =~ /:(.*)\./

    key_hash = $1
    salt     = $'

    salt = [salt].pack 'H*'

    expected_key = Digest::SHA512.digest "password#{salt}"
    expected_key_hash = Digest::SHA512.hexdigest expected_key

    assert_equal expected_key_hash, key_hash

    expected = <<-EXPECTED
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Foo: bar\r
\r
\r
    EXPECTED

    assert_equal expected, body
  end

  def test_packet_icon_utf_8
    packet = @gntp.packet 'REGISTER', ['Foo: π'], 1 => Growl::RUBY_LOGO_PNG

    assert_equal Encoding::BINARY, packet.encoding
  end

  def test_packet_notify
    expected = <<-EXPECTED
GNTP/1.0 NOTIFY NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notification-ID: 4\r
Notification-Name: test-note\r
Notification-Title: title\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_notify('test-note', 'title',
                                               nil, 0, false, nil, nil)
  end

  def test_packet_notify_callback
    expected = <<-EXPECTED
GNTP/1.0 NOTIFY NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notification-ID: 4\r
Notification-Name: test-note\r
Notification-Title: title\r
Notification-Callback-Context: context\r
Notification-Callback-Context-Type: type\r
\r
\r
    EXPECTED

    result = @gntp.packet_notify 'test-note', 'title', nil, 0, false, nil, true

    assert_equal expected, result
  end

  def test_packet_notify_callback_url
    expected = <<-EXPECTED
GNTP/1.0 NOTIFY NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notification-ID: 4\r
Notification-Name: test-note\r
Notification-Title: title\r
Notification-Callback-Context: context\r
Notification-Callback-Context-Type: type\r
Notification-Callback-Target: http://example\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_notify('test-note', 'title',
                                               nil, 0, false, nil,
                                               'http://example')
  end

  def test_packet_notify_coalesce
    expected = <<-EXPECTED
GNTP/1.0 NOTIFY NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notification-ID: 4\r
Notification-Coalescing-ID: 3\r
Notification-Name: test-note\r
Notification-Title: title\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_notify('test-note', 'title',
                                               nil, 0, false, 3, nil)
  end

  def test_packet_notify_description
    expected = <<-EXPECTED
GNTP/1.0 NOTIFY NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notification-ID: 4\r
Notification-Name: test-note\r
Notification-Title: title\r
Notification-Text: message\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_notify('test-note', 'title', 'message',
                                               0, false, nil, nil)
  end

  def test_packet_notify_icon
    @gntp.add_notification 'test-note', nil, @jpg_url

    expected = <<-EXPECTED
GNTP/1.0 NOTIFY NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notification-ID: 4\r
Notification-Name: test-note\r
Notification-Title: title\r
Notification-Icon: x-growl-resource://4\r
\r
Identifier: 4\r
Length: #{@jpg_url.size}\r
\r
#{@jpg_url}\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_notify('test-note', 'title',
                                               nil, 0, false, nil, nil)
  end

  def test_packet_notify_icon_uri
    uri = URI 'http://example/icon.png'
    @gntp.add_notification 'test-note', nil, uri

    expected = <<-EXPECTED
GNTP/1.0 NOTIFY NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notification-ID: 4\r
Notification-Name: test-note\r
Notification-Title: title\r
Notification-Icon: http://example/icon.png\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_notify('test-note', 'title',
                                               nil, 0, false, nil, nil)
  end

  def test_packet_notify_priority
    expected = <<-EXPECTED
GNTP/1.0 NOTIFY NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notification-ID: 4\r
Notification-Name: test-note\r
Notification-Title: title\r
Notification-Priority: 2\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_notify('test-note', 'title',
                                               nil, 2, false, nil, nil)

    assert_match(%r%^Notification-Priority: -2%,
                 @gntp.packet_notify('test-note', 'title', nil,
                                     -2, false, nil, nil))
    assert_match(%r%^Notification-Priority: -1%,
                 @gntp.packet_notify('test-note', 'title', nil,
                                     -1, false, nil, nil))
    refute_match(%r%^Notification-Priority: 0%,
                 @gntp.packet_notify('test-note', 'title', nil,
                                     0, false, nil, nil))
    assert_match(%r%^Notification-Priority: 1%,
                 @gntp.packet_notify('test-note', 'title', nil,
                                     1, false, nil, nil))
    assert_match(%r%^Notification-Priority: 2%,
                 @gntp.packet_notify('test-note', 'title', nil,
                                     2, false, nil, nil))

    e = assert_raises ArgumentError do
      @gntp.packet_notify 'test-note', 'title', nil, -3, false, nil, nil
    end

    assert_equal 'invalid priority level -3', e.message

    e = assert_raises ArgumentError do
      @gntp.packet_notify 'test-note', 'title', nil, 3, false, nil, nil
    end

    assert_equal 'invalid priority level 3', e.message
  end

  def test_packet_notify_sticky
    expected = <<-EXPECTED
GNTP/1.0 NOTIFY NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notification-ID: 4\r
Notification-Name: test-note\r
Notification-Title: title\r
Notification-Sticky: True\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_notify('test-note', 'title',
                                               nil, 0, true, nil, nil)

    refute_match(%r%^Notification-Sticky:%,
                 @gntp.packet_notify('test-note', 'title', nil, 0, false,
                                     nil, nil))
  end

  def test_packet_register
    @gntp.add_notification 'test-note'

    expected = <<-EXPECTED
GNTP/1.0 REGISTER NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notifications-Count: 1\r
\r
Notification-Name: test-note\r
Notification-Enabled: true\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_register
  end

  def test_packet_register_application_icon
    @gntp.add_notification 'test-note'
    @gntp.icon = @jpg_url

    expected = <<-EXPECTED
GNTP/1.0 REGISTER NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Application-Icon: x-growl-resource://4\r
Notifications-Count: 1\r
\r
Notification-Name: test-note\r
Notification-Enabled: true\r
\r
Identifier: 4\r
Length: #{@jpg_url.size}\r
\r
#{@jpg_url}\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_register
  end

  def test_packet_register_application_icon_uri
    @gntp.add_notification 'test-note'
    @gntp.icon = URI 'http://example/icon.png'

    expected = <<-EXPECTED
GNTP/1.0 REGISTER NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Application-Icon: http://example/icon.png\r
Notifications-Count: 1\r
\r
Notification-Name: test-note\r
Notification-Enabled: true\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_register
  end

  def test_packet_register_disabled
    @gntp.add_notification 'test-note', nil, nil, false

    expected = <<-EXPECTED
GNTP/1.0 REGISTER NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notifications-Count: 1\r
\r
Notification-Name: test-note\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_register
  end

  def test_packet_register_display_name
    @gntp.add_notification 'test-note', 'Test Note'

    expected = <<-EXPECTED
GNTP/1.0 REGISTER NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notifications-Count: 1\r
\r
Notification-Name: test-note\r
Notification-Display-Name: Test Note\r
Notification-Enabled: true\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_register
  end

  def test_packet_register_notification_icon
    @gntp.add_notification 'test-note', nil, @jpg_url

    expected = <<-EXPECTED
GNTP/1.0 REGISTER NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notifications-Count: 1\r
\r
Notification-Name: test-note\r
Notification-Enabled: true\r
Notification-Icon: x-growl-resource://4\r
\r
Identifier: 4\r
Length: #{@jpg_url.size}\r
\r
#{@jpg_url}\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_register
  end

  def test_packet_register_notification_icon_uri
    uri = URI 'http://example/icon.png'
    @gntp.add_notification 'test-note', nil, uri

    expected = <<-EXPECTED
GNTP/1.0 REGISTER NONE\r
Application-Name: test-app\r
Origin-Software-Name: ruby-growl\r
Origin-Software-Version: #{Growl::VERSION}\r
Origin-Platform-Name: ruby\r
Origin-Platform-Version: #{RUBY_VERSION}\r
Connection: close\r
Notifications-Count: 1\r
\r
Notification-Name: test-note\r
Notification-Enabled: true\r
Notification-Icon: http://example/icon.png\r
\r
\r
    EXPECTED

    assert_equal expected, @gntp.packet_register
  end

  def test_parse_header_boolean
    assert_equal ['Notification-Enabled', true],
                 @gntp.parse_header('Notification-Enabled', 'True')
    assert_equal ['Notification-Enabled', true],
                 @gntp.parse_header('Notification-Enabled', 'Yes')
    assert_equal ['Notification-Sticky', false],
                 @gntp.parse_header('Notification-Sticky', 'False')
    assert_equal ['Notification-Sticky', false],
                 @gntp.parse_header('Notification-Sticky', 'No')
  end

  def test_parse_header_date
    now = Time.at Time.now.to_i
    now_8601 = now.iso8601
    assert_equal ['Notification-Callback-Timestamp', now],
                 @gntp.parse_header('Notification-Callback-Timestamp', now_8601)
  end

  def test_parse_header_integer
    assert_equal ['Error-Code', 200],
                 @gntp.parse_header('Error-Code', '200')
    assert_equal ['Notifications-Count', 2],
                 @gntp.parse_header('Notifications-Count', '2')
    assert_equal ['Notifications-Priority', 2],
                 @gntp.parse_header('Notifications-Priority', '2')
    assert_equal ['Subscriber-Port', 23053],
                 @gntp.parse_header('Subscriber-Port', '23053')
    assert_equal ['Subscription-TTL', 60],
                 @gntp.parse_header('Subscription-TTL', '60')
  end

  def test_parse_header_string
    value = 'test'
    value.encode! Encoding::BINARY

    header = @gntp.parse_header('Application-Name', value)
    assert_equal ['Application-Name', 'test'], header
    assert_equal Encoding::UTF_8, header.last.encoding

    header = @gntp.parse_header('Application-Name', '(null)')
    assert_equal ['Application-Name', nil], header

    assert_equal ['Application-Name', 'test'],
                 @gntp.parse_header('Application-Name', 'test')
    assert_equal ['Error-Description', 'test'],
                 @gntp.parse_header('Error-Description', 'test')
    assert_equal ['Notification-Name', 'test'],
                 @gntp.parse_header('Notification-Name', 'test')
    assert_equal ['Notification-Display-Name', 'test'],
                 @gntp.parse_header('Notification-Display-Name', 'test')
    assert_equal ['Notification-ID', 'test'],
                 @gntp.parse_header('Notification-ID', 'test')
    assert_equal ['Notification-Title', 'test'],
                 @gntp.parse_header('Notification-Title', 'test')
    assert_equal ['Notification-Text', 'test'],
                 @gntp.parse_header('Notification-Text', 'test')
    assert_equal ['Notification-Coalescing-ID', 'test'],
                 @gntp.parse_header('Notification-Coalescing-ID', 'test')
    assert_equal ['Notification-Callback-Context', 'test'],
                 @gntp.parse_header('Notification-Callback-Context', 'test')
    assert_equal ['Notification-Callback-Context-Type', 'test'],
                 @gntp.parse_header('Notification-Callback-Context-Type', 'test')
    assert_equal ['Notification-Callback-Result', 'test'],
                 @gntp.parse_header('Notification-Callback-Result', 'test')
    assert_equal ['Notification-Callback-Target', 'test'],
                 @gntp.parse_header('Notification-Callback-Target', 'test')
    assert_equal ['Subscriber-ID', 'test'],
                 @gntp.parse_header('Subscriber-ID', 'test')
    assert_equal ['Subscriber-Name', 'test'],
                 @gntp.parse_header('Subscriber-Name', 'test')
    assert_equal ['Origin-Machine-Name', 'test'],
                 @gntp.parse_header('Origin-Machine-Name', 'test')
    assert_equal ['Origin-Sofware-Name', 'test'],
                 @gntp.parse_header('Origin-Sofware-Name', 'test')
    assert_equal ['Origin-Software-Version', 'test'],
                 @gntp.parse_header('Origin-Software-Version', 'test')
    assert_equal ['Origin-Platform-Name', 'test'],
                 @gntp.parse_header('Origin-Platform-Name', 'test')
    assert_equal ['Origin-Platform-Version', 'test'],
                 @gntp.parse_header('Origin-Platform-Version', 'test')
  end

  def test_parse_header_url
    http = URI 'http://example/some?page'

    assert_equal ['Application-Icon', http],
                 @gntp.parse_header('Application-Icon',
                                    'http://example/some?page')

    res = URI 'x-growl-resource://unique'
    assert_equal ['Notification-Icon', res],
                 @gntp.parse_header('Notification-Icon',
                                    'x-growl-resource://unique')
  end

  def test_receive_callback
    packet = <<-PACKET
GNTP/1.0 -CALLBACK NONE\r
Response-Action: NOTIFY\r
Notification-ID: 4\r
Notification-Callback-Result: CLICKED\r
Notification-Callback-Timestamp: 2012-03-28\r
Notification-Callback-Context: context\r
Notification-Callback-Context-Type: type\r
Application-Name: test\r
    PACKET

    headers = @gntp.receive packet

    expected = {
      'Response-Action'                    => 'NOTIFY',
      'Notification-ID'                    => '4',
      'Notification-Callback-Result'       => 'CLICKED',
      'Notification-Callback-Timestamp'    => Time.parse('2012-03-28'),
      'Notification-Callback-Context'      => 'context',
      'Notification-Callback-Context-Type' => 'type',
      'Application-Name'                   => 'test'
    }

    assert_equal expected, headers
  end

  def test_receive_error
    packet = "GNTP/1.0 -ERROR NONE\r\nResponse-Action: (null)\r\n" \
             "Error-Description: (null)\r\nError-Code: 200\r\n\r\n\r\n"

    e = assert_raises Growl::GNTP::TimedOut do
      @gntp.receive packet
    end

    expected = {
      'Error-Code'        => 200,
      'Error-Description' => nil,
      'Response-Action'   => nil,
    }

    assert_equal expected, e.headers

    packet = "GNTP/1.0 -ERROR NONE\r\nResponse-Action: (null)\r\n" \
             "Error-Description: (null)\r\nError-Code: 201\r\n\r\n\r\n"

    assert_raises Growl::GNTP::NetworkFailure do
      @gntp.receive packet
    end

    packet = "GNTP/1.0 -ERROR NONE\r\nResponse-Action: (null)\r\n" \
             "Error-Description: (null)\r\nError-Code: 300\r\n\r\n\r\n"

    assert_raises Growl::GNTP::InvalidRequest do
      @gntp.receive packet
    end

    packet = "GNTP/1.0 -ERROR NONE\r\nResponse-Action: (null)\r\n" \
             "Error-Description: (null)\r\nError-Code: 301\r\n\r\n\r\n"

    assert_raises Growl::GNTP::UnknownProtocol do
      @gntp.receive packet
    end

    packet = "GNTP/1.0 -ERROR NONE\r\nResponse-Action: (null)\r\n" \
             "Error-Description: (null)\r\nError-Code: 302\r\n\r\n\r\n"

    assert_raises Growl::GNTP::UnknownProtocolVersion do
      @gntp.receive packet
    end

    packet = "GNTP/1.0 -ERROR NONE\r\nResponse-Action: (null)\r\n" \
             "Error-Description: (null)\r\nError-Code: 303\r\n\r\n\r\n"

    assert_raises Growl::GNTP::RequiredHeaderMissing do
      @gntp.receive packet
    end

    packet = "GNTP/1.0 -ERROR NONE\r\nResponse-Action: (null)\r\n" \
             "Error-Description: (null)\r\nError-Code: 400\r\n\r\n\r\n"

    assert_raises Growl::GNTP::NotAuthorized do
      @gntp.receive packet
    end

    packet = "GNTP/1.0 -ERROR NONE\r\nResponse-Action: (null)\r\n" \
             "Error-Description: (null)\r\nError-Code: 401\r\n\r\n\r\n"

    assert_raises Growl::GNTP::UnknownApplication do
      @gntp.receive packet
    end

    packet = "GNTP/1.0 -ERROR NONE\r\nResponse-Action: (null)\r\n" \
             "Error-Description: (null)\r\nError-Code: 402\r\n\r\n\r\n"

    assert_raises Growl::GNTP::UnknownNotification do
      @gntp.receive packet
    end

    packet = "GNTP/1.0 -ERROR NONE\r\nResponse-Action: (null)\r\n" \
             "Error-Description: (null)\r\nError-Code: 403\r\n\r\n\r\n"

    assert_raises Growl::GNTP::AlreadyProcessed do
      @gntp.receive packet
    end

    packet = "GNTP/1.0 -ERROR NONE\r\nResponse-Action: (null)\r\n" \
             "Error-Description: (null)\r\nError-Code: 404\r\n\r\n\r\n"

    assert_raises Growl::GNTP::NotificationDisabled do
      @gntp.receive packet
    end

    packet = "GNTP/1.0 -ERROR NONE\r\nResponse-Action: (null)\r\n" \
             "Error-Description: (null)\r\nError-Code: 500\r\n\r\n\r\n"

    assert_raises Growl::GNTP::InternalServerError do
      @gntp.receive packet
    end
  end

  def test_receive_ok
    packet = "\r\nGNTP/1.0 -OK NONE\r\nResponse-Action: REGISTER\r\n\r\n\r\n"

    headers = @gntp.receive packet

    expected = {
      'Response-Action' => 'REGISTER'
    }

    assert_equal expected, headers
  end

  def test_salt
    salt = @gntp.salt

    assert_kind_of String, salt
    assert_equal 16, salt.length
  end

  def test_send
    stub_socket "GNTP/1.0 -OK NONE\r\nResponse-Action: REGISTER\r\n\r\n\r\n"

    result = @gntp.send "hello"

    expected = {
      'Response-Action' => 'REGISTER'
    }

    assert_equal expected, result

    assert_equal "hello", @gntp._socket._output.string

    assert_empty @gntp._socket.read.strip
  end

  def assert_endecrypt cipher, key, iv
    encrypted = cipher.update 'this is a test payload'
    encrypted << cipher.final

    plain = decrypt cipher, key, iv, encrypted

    assert_equal 'this is a test payload', plain
  end

  def decrypt cipher, key, iv, encrypted
    decipher = OpenSSL::Cipher.new cipher.name
    decipher.decrypt
    decipher.key = key
    decipher.iv = iv

    plain = decipher.update encrypted
    plain << decipher.final

    plain
  end

  def stub_salt
    def @gntp.salt
      [152, 215, 233, 14, 170, 24, 254, 65].pack 'C*'
    end
  end

  def stub_socket response
    @gntp.instance_variable_set :@_response, response
    def @gntp.connect
      @_socket = Socket.new
      @_socket._input = @_response
      @_socket
    end

    def @gntp._socket
      @_socket
    end
  end

end

