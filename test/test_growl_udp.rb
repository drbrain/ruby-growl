require 'minitest/autorun'
require 'ruby-growl'

class TestGrowlUDP < Minitest::Test

  def setup
    @growl = Growl::UDP.new "localhost", "ruby-growl test",
                            ["ruby-growl Test Notification"]
  end

  def test_notify_priority
    assert_raises Growl::Error do
      @growl.notify "ruby-growl Test Notification", "", "", -3
    end

    -2.upto 2 do |priority|
      @growl.notify "ruby-growl Test Notification",
                      "Priority #{priority}",
                      "This message should have a priority set.", priority
    end

    assert_raises RuntimeError do
      @growl.notify "ruby-growl Test Notification", "", "", 3
    end

  rescue SystemCallError => e
    skip "#{e.class}: #{e.message}"
  end

  def test_notify_notify_type
    assert_raises Growl::Error do
      @growl.notify "bad notify type", "", ""
    end

    @growl.notify "ruby-growl Test Notification", "Empty",
                  "This notification is empty."

  rescue SystemCallError => e
    skip "#{e.class}: #{e.message}"
  end

  def test_notify_sticky
    @growl.notify "ruby-growl Test Notification", "Sticky",
                  "This notification should be sticky.", 0, true

  rescue SystemCallError => e
    skip "#{e.class}: #{e.message}"
  end

  def test_registration_packet
    @growl = Growl::UDP.new "localhost", "growlnotify",
                            ["Command-Line Growl Notification"]

    expected = [
      "01", "00", "00", "0b",  "01", "01", "67", "72", # ......gr
      "6f", "77", "6c", "6e",  "6f", "74", "69", "66", # owlnotif
      "79", "00", "1f", "43",  "6f", "6d", "6d", "61", # y..Comma
      "6e", "64", "2d", "4c",  "69", "6e", "65", "20", # nd-Line.
      "47", "72", "6f", "77",  "6c", "20", "4e", "6f", # Growl.No
      "74", "69", "66", "69",  "63", "61", "74", "69", # tificati
      "6f", "6e", "00", "57",  "4a", "e3", "1b", "a5", # on.WJ...
      "49", "9c", "25", "3a",  "be", "75", "5d", "e5", # I.%:.u].
      "2c", "c9", "96"                                 # ,..
    ]

    packet = @growl.registration_packet

    assert_equal expected, util_hexes(packet)
  end

  def test_notification_packet
    @growl = Growl::UDP.new "localhost", "growlnotify",
                            ["Command-Line Growl Notification"]

    expected = [
      "01", "01", "00", "00",  "00", "1f", "00", "00", # ........
      "00", "02", "00", "0b",  "43", "6f", "6d", "6d", # ....Comm
      "61", "6e", "64", "2d",  "4c", "69", "6e", "65", # and-Line
      "20", "47", "72", "6f",  "77", "6c", "20", "4e", # .Growl.N
      "6f", "74", "69", "66",  "69", "63", "61", "74", # otificat
      "69", "6f", "6e", "68",  "69", "67", "72", "6f", # ionhigro
      "77", "6c", "6e", "6f",  "74", "69", "66", "79", # wlnotify
      "7f", "9c", "a0", "dd",  "b6", "6b", "64", "75", # .....kdu
      "99", "c4", "4e", "7b",  "f1", "b2", "5b", "e2", # ..N{..[.
    ]

    packet = @growl.notification_packet "Command-Line Growl Notification",
                                        "", "hi", 0, false

    assert_equal expected, util_hexes(packet)
  end

  def test_notification_packet_priority_negative_2
    @growl = Growl::UDP.new "localhost", "growlnotify",
                            ["Command-Line Growl Notification"]

    expected = [
      "01", "01", "0c", "00",  "00", "1f", "00", "00", # ........
      "00", "02", "00", "0b",  "43", "6f", "6d", "6d", # ....Comm
      "61", "6e", "64", "2d",  "4c", "69", "6e", "65", # and-Line
      "20", "47", "72", "6f",  "77", "6c", "20", "4e", # .Growl.N
      "6f", "74", "69", "66",  "69", "63", "61", "74", # otificat
      "69", "6f", "6e", "68",  "69", "67", "72", "6f", # ionhigro
      "77", "6c", "6e", "6f",  "74", "69", "66", "79", # wlnotify
      "64", "b4", "cc", "a8",  "74", "ea", "30", "2d",
      "6e", "0f", "c1", "45",  "b2", "b5", "58", "00"
    ]

    packet = @growl.notification_packet "Command-Line Growl Notification",
                                        "", "hi", -2, false

    assert_equal expected, util_hexes(packet)
  end

  def test_notification_packet_priority_negative_1
    @growl = Growl::UDP.new "localhost", "growlnotify",
                            ["Command-Line Growl Notification"]

    expected = [
      "01", "01", "0e", "00",  "00", "1f", "00", "00", # ........
      "00", "02", "00", "0b",  "43", "6f", "6d", "6d", # ....Comm
      "61", "6e", "64", "2d",  "4c", "69", "6e", "65", # and-Line
      "20", "47", "72", "6f",  "77", "6c", "20", "4e", # .Growl.N
      "6f", "74", "69", "66",  "69", "63", "61", "74", # otificat
      "69", "6f", "6e", "68",  "69", "67", "72", "6f", # ionhigro
      "77", "6c", "6e", "6f",  "74", "69", "66", "79", # wlnotify
      "19", "17", "9f", "84",  "6d", "19", "c6", "04",
      "8e", "6d", "8d", "84",  "05", "84", "5b"
    ]

    packet = @growl.notification_packet "Command-Line Growl Notification",
                                        "", "hi", -1, false

    assert_equal expected, util_hexes(packet)
  end

  def test_notification_packet_priority_1
    @growl = Growl::UDP.new "localhost", "growlnotify",
                            ["Command-Line Growl Notification"]

    expected = [
      "01", "01", "02", "00",  "00", "1f", "00", "00", # ........
      "00", "02", "00", "0b",  "43", "6f", "6d", "6d", # ....Comm
      "61", "6e", "64", "2d",  "4c", "69", "6e", "65", # and-Line
      "20", "47", "72", "6f",  "77", "6c", "20", "4e", # .Growl.N
      "6f", "74", "69", "66",  "69", "63", "61", "74", # otificat
      "69", "6f", "6e", "68",  "69", "67", "72", "6f", # ionhigro
      "77", "6c", "6e", "6f",  "74", "69", "66", "79", # wlnotify
      "03", "4d", "92", "cf",  "5f", "6c", "c2", "4c",
      "4c", "f4", "f2", "b5",  "24", "d3", "ae", "96"
    ]

    packet = @growl.notification_packet "Command-Line Growl Notification",
                                        "", "hi", 1, false

    packet = util_hexes(packet)

    assert_equal expected, packet
  end

  def test_notification_packet_priority_2
    @growl = Growl::UDP.new "localhost", "growlnotify",
                            ["Command-Line Growl Notification"]

    expected = [
      "01", "01", "04", "00",  "00", "1f", "00", "00", # ........
      "00", "02", "00", "0b",  "43", "6f", "6d", "6d", # ....Comm
      "61", "6e", "64", "2d",  "4c", "69", "6e", "65", # and-Line
      "20", "47", "72", "6f",  "77", "6c", "20", "4e", # .Growl.N
      "6f", "74", "69", "66",  "69", "63", "61", "74", # otificat
      "69", "6f", "6e", "68",  "69", "67", "72", "6f", # ionhigro
      "77", "6c", "6e", "6f",  "74", "69", "66", "79", # wlnotify
      "68", "91", "f7", "82",  "20", "7f", "1b", "08",
      "98", "a3", "1b", "f6",  "cc", "72", "39", "94"
    ]

    packet = @growl.notification_packet "Command-Line Growl Notification",
                                        "", "hi", 2, false

    assert_equal expected, util_hexes(packet)
  end

  def test_notification_packet_priority_sticky
    @growl = Growl::UDP.new "localhost", "growlnotify",
                            ["Command-Line Growl Notification"]

    expected = [
      "01", "01", "01", "00",  "00", "1f", "00", "00", # ........
      "00", "02", "00", "0b",  "43", "6f", "6d", "6d", # ....Comm
      "61", "6e", "64", "2d",  "4c", "69", "6e", "65", # and-Line
      "20", "47", "72", "6f",  "77", "6c", "20", "4e", # .Growl.N
      "6f", "74", "69", "66",  "69", "63", "61", "74", # otificat
      "69", "6f", "6e", "68",  "69", "67", "72", "6f", # ionhigro
      "77", "6c", "6e", "6f",  "74", "69", "66", "79", # wlnotify
      "94", "b7", "66", "74",  "02", "ee", "78", "33",
      "c2", "a4", "54", "b2",  "3b", "77", "5e", "27"
    ]

    packet = @growl.notification_packet "Command-Line Growl Notification",
                                        "", "hi", 0, true

    assert_equal expected, util_hexes(packet)
  end

  def test_socket
    @udp = Growl::UDP.allocate

    socket = @udp.socket "localhost"

    refute socket.getsockopt(:SOL_SOCKET, :SO_BROADCAST).bool
  end

  def test_socket_broadcast
    @udp = Growl::UDP.allocate

    socket = @udp.socket "255.255.255.255"

    assert socket.getsockopt(:SOL_SOCKET, :SO_BROADCAST).bool
  end

  def test_socket_subnet_broadcast
    skip "Socket.getifaddrs not supported" unless
      Socket.respond_to? :getifaddrs

    ifaddr = Socket.getifaddrs.find { |ifaddr| ifaddr.broadaddr }

    @udp = Growl::UDP.allocate

    socket = @udp.socket ifaddr.broadaddr.ip_address

    assert socket.getsockopt(:SOL_SOCKET, :SO_BROADCAST).bool
  end

  def util_hexes string
    if string.respond_to? :ord then
      string.scan(/./).map { |c| "%02x" % c.ord }
    else
      string.scan(/./).map { |c| "%02x" % c[0] }
    end
  end

end

