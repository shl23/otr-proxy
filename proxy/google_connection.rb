class GoogleConnection
  include Celluloid::IO

  ENCRYPTED = Java::NetJavaOtr4jSession::SessionStatus::ENCRYPTED

  attr_reader :keystore
  trap_exit :close_connections

  def initialize(conn, server, port)
    debug "* Connecting to proxy target #{server}:#{port}"

    @keystore = KeyManager.new
    @otr_engine = OtrEngineHost.new(self)
    @otr_states = {}
    @otr_fast_conn = {}
    @otr_mutex = Mutex.new

    @local = conn

    @remote = SSLSocket.new(TCPSocket.new(server, port))
    @remote.connect

    async.handle_local
    async.handle_remote
  end

  # Proxies
  def handle_local
    while true do
      parse_message(@local, @remote, :local)
    end

  rescue Exception => ex
    self.handle_error(ex)
  end

  def handle_remote
    while true do
      parse_message(@remote, @local, :remote)
    end

  rescue Exception => ex
    self.handle_error(ex)
  end

  def handle_error(ex)
    puts
    puts "#{ex.class}: #{ex.message}"
    puts ex.backtrace

    close_connections
    Celluloid.shutdown
  end

  def close_connections
    puts "** Closing connections"

    @remote.close rescue nil
    @local.close rescue nil
  end

  # Message handling
  def parse_message(receiver, sender, type)
    msg, tag = "", nil
    while true do
      # Grab from socket
      data = receiver.readpartial(4096)

      msg << data if data

      # Figure out the tag we're working with
      unless tag
        tag = msg.match(/^<([a-z:]+)(\s.+)?>/)
        tag = tag[1] if tag

        # Not a message, we don't care about inspecting it closer
        if !tag || tag != "message"
          break
        end
      end

      # See if we've finished reading
      break if data =~ /<\/message>$/
    end

    verbose
    verbose "[#{type}] #{msg}"

    msg = self.send(:"parse_#{type}_message", msg, tag)

    # Send it off to the proxy
    sender.write(msg) if msg
  end

  # Remote message we received
  def parse_remote_message(msg, tag)
    # Parse message if needed
    if tag == "message"
      doc = Nokogiri::XML(msg)

      body_node = doc.xpath("/message//body").first
      body = body_node.text if body_node

      # Initializing an OTR session
      if body =~ /^\?OTR\?v(1|2)\?/
        status = self.start_remote_otr($1, doc)
        return unless status

      # Handling an OTR message
      elsif body =~ /^?OTR:/
        status = self.handle_remote_otr(doc, body)
        return unless status

      # Handle bad encoding to strip out random tab/spaces
      elsif body && body =~ /(\t|\s)$/
        body_node.content = body.strip
        msg = doc.to_xml.split("\n", 2).last
      end

    # Figure out our JID
    elsif !@jid && tag == "iq" && msg =~ /type="result"/
      match = msg.match(/<jid>(.+)\/(.+)<\/jid>/)
      @jid = {:email => match[1], :id => match[2], :full => "#{match[1]}/#{match[2]}"}
    end

    msg
  end

  # Local message being sent out
  def parse_local_message(msg, tag)
    if tag == "message"
      doc = Nokogiri::XML(msg)

      body_node = doc.xpath("/message//body").first
      body = body_node.text if body_node

      status = self.handle_local_otr(doc, body)
      return unless status
    end

    msg
  end

  def extract_targets(doc, fakeFrom=false)
    # Figure out who the message is going to
    receiver = doc.xpath("/message/@to").first.to_s
    sender = doc.xpath("/message/@from").first.to_s
    sender = @jid[:full] if fakeFrom && sender == ""

    if receiver != "" && sender != ""
      return sender, receiver
    end
  end

  # Find an OTR session without the ID
  def find_session(target)
    # We already have an ID we can use
    return @otr_states[target] if target =~ /\//

    @otr_states.each do |id, otr|
      id = id.split("/", 2).first

      if id == target
        return otr
      end
    end

    nil
  end

  # Initialize OTR
  def initialize_otr(them, us, fastInit=nil)
    debug "** Initializing OTR states to #{them} (us #{us})"

    # Initialize everything where needed
    otr = @otr_states[them] ||= {}
    otr[:state] ||= :handshake
    otr[:self_session] ||= Java::NetJavaOtr4jSession::SessionID.new(us, them, "XMPP")
    otr[:them_session] ||= Java::NetJavaOtr4jSession::SessionID.new(them, us, "XMPP")

    otr[:self_impl] = Java::NetJavaOtr4j::OtrEngineImpl.new(@otr_engine)
    otr[:self_impl].startSession(otr[:self_session])

    otr[:them_impl] ||= Java::NetJavaOtr4j::OtrEngineImpl.new(@otr_engine)
    otr[:them_impl].startSession(otr[:them_session])

    self.send_simple(@remote, them, @otr_engine.last_injection) unless fastInit

    # This is a quick initialize, we need to tell them we're interested
    # but we don't want to go through the whole handshake
    unless them =~ /\//
      debug "*** Generic OTR for #{them}, waiting for specific"
      @otr_states.delete(them)
      return
    end

    otr
  end

  # Local OTR
  def handle_local_otr(doc, body)
    return true unless body

    sender, receiver = self.extract_targets(doc, true)
    return true unless sender

    @otr_mutex.synchronize do
      otr = self.find_session(receiver)

      # See active fingerprint
      if body == "!fp"
        self.reset_typing_status(@remote, receiver)

        if otr
          self.check_remote_key(otr)
        else
          self.send_raw(@local, self.construct_chat(receiver, sender, "[No OTR] Cannot verify as we are not running through OTR."))
        end

      # See our fingerprint
      elsif body == "!myfp"
        self.reset_typing_status(@remote, receiver)

        if otr
          pair = @keystore.loadPair(@keystore.createPairID(otr[:self_session]))
          if pair
            msg = "[Self Key] Our fingerprint for #{sender.split("/", 2).first} is #{@keystore.readablePublic(pair.getPublic())}."
          else
            msg = "[Self Key] Not established yet, need a message from the target first."
          end

        else
          msg = "[No OTR] Cannot verify as we are not running through OTR."
        end

        self.send_raw(@local, self.construct_chat(receiver, sender, msg))

      # Verify it as good
      elsif body == "!verify"
        self.reset_typing_status(@remote, receiver)

        if otr
          self.verify_remote_key(otr)
        else
          self.send_raw(@local, self.construct_chat(receiver, sender, "[No OTR] Cannot verify as we are not running through OTR."))
        end

      # Check we're running
      elsif body == "!ping"
        self.reset_typing_status(@remote, receiver)
        self.send_raw(@local, self.construct_chat(receiver, sender, "pong"))

      # Start OTR
      elsif body == "!otr"
        self.reset_typing_status(@remote, receiver)

        if otr
          self.send_raw(@local, self.construct_chat(receiver, sender, "[OTR] We're already using OTR"))
        else
          self.send_raw(@local, self.construct_chat(receiver, sender, "[OTR] Starting OTR negotiation process"))
          self.initialize_otr(receiver, sender)
        end

      # Encrypt our message
      elsif otr
        msg = otr[:self_impl].transformSending(otr[:self_session], body)

        data = <<XML
<message from="#{sender}" to="#{receiver}" id="#{self.generateMsgID}" type="chat"><active xmlns="http://jabber.org/protocol/chatstates"/><body>#{msg}</body><nos:x value="enabled" xmlns:nos="google:nosave"/><arc:record otr="true" xmlns:arc="http://jabber.org/protocol/archive"/></message>
XML
        self.send_raw(@remote, data.strip)

      # Unknown, handle normally
      else
        return true
      end
    end

    nil
  end

  # Remote OTR
  def check_remote_key(otr)
    sender, receiver = otr[:self_session].getUserID(), otr[:self_session].getAccountID()

    # Make sure we have a remote key
    remoteKey = otr[:self_impl].getRemotePublicKey(otr[:self_session])
    unless remoteKey
      self.send_raw(@local, self.construct_chat(sender, receiver, "[Key FAIL] Cannot find remote key for #{sender}"))
      return
    end

    remoteKeyPlain = @keystore.readablePublic(remoteKey)
    remoteID = @keystore.createRemoteID(otr[:them_session])

    # Verify we have a match
    if @keystore.hasRemote?(remoteID)
      oldRemoteKey = @keystore.loadRemote(remoteID)
      if oldRemoteKey == remoteKey
        self.send_raw(@local, self.construct_chat(sender, receiver, "[Key Match] Fingerprint for #{sender} is #{remoteKeyPlain}"))
      else
        self.send_raw(@local, self.construct_chat(sender, receiver, "[KEY MISMATCH] Fingerprint for #{sender} is #{remoteKeyPlain} and was #{@keystore.readablePublic(oldRemoteKey)}"))
      end

    # First time OTRing, log the fingerprint
    else
      self.send_raw(@local, self.construct_chat(sender, receiver, "[New Key] Fingerprint for #{sender} is #{remoteKeyPlain}"))
    end
  end

  def verify_remote_key(otr)
    sender, receiver = otr[:self_session].getUserID(), otr[:self_session].getAccountID()

    # Make sure we have a remote key
    remoteKey = otr[:self_impl].getRemotePublicKey(otr[:self_session])
    unless remoteKey
      self.send_raw(@local, self.construct_chat(sender, receiver, "[Key FAIL] Cannot find remote key for #{sender}"))
      return
    end

    remoteKeyPlain = @keystore.readablePublic(remoteKey)
    remoteID = @keystore.createRemoteID(otr[:them_session])
    @keystore.saveRemote(remoteID, remoteKey)

    self.send_raw(@local, self.construct_chat(sender, receiver, "[Key Verified] Fingerprint for #{sender} is saved as #{remoteKeyPlain}"))
  end

  def start_remote_otr(version, doc)
    sender, receiver = self.extract_targets(doc)
    return true unless sender

    @otr_mutex.synchronize do
      @otr_states.delete(sender)

      otr = self.initialize_otr(sender, receiver)
      otr[:version] = version
    end

    nil
  end

  def handle_remote_otr(doc, body)
    sender, receiver = self.extract_targets(doc)
    return true unless sender

    @otr_mutex.synchronize do
      otr = @otr_states[sender] || {}
      if !@otr_fast_conn[sender] && otr.empty? && @keystore.hasPairByAddresses?(receiver, sender)
        debug "** Trying fast initialize for #{sender}"
        otr = self.initialize_otr(sender, receiver, true)
      end

      debug
      debug "** Handling OTR for #{sender} (receiver #{receiver}), state #{otr[:state]}, v#{otr[:version]}"

      # We sent a confirmation on OTR to them got the commit back and now sent the DH Key
      if otr[:state] == :handshake || otr[:state] == :dh_key
        otr[:state] = otr[:state] == :handshake ? :dh_key : :authed
        otr[:fully_encrypted] = true if otr[:authed]

        otr[:self_impl].transformReceiving(otr[:self_session], body)
        self.send_simple(@remote, sender, @otr_engine.last_injection)

        # We authenticated, can do another fast conn if something happens
        @otr_fast_conn.delete(sender)

        # Report the keys we're using
        if otr[:state] == :authed && !otr[:fully_encrypted]
          otr[:fully_encrypted] = true

          # Output fingerprints
          self.check_remote_key(otr)
        end

        # We had a pending message that we couldn't decrypt, tell them to resend
        if otr[:state] == :authed && otr.delete(:pending_msg)
          debug "*** Had pending message, sending an error that we didn't receive it"

          error_type = Java::NetJavaOtr4jIoMessages::AbstractMessage::MESSAGE_ERROR
          msg = Java::NetJavaOtr4jIoMessages::ErrorMessage.new(error_type, @otr_engine.getReplyForUnreadableMessage)
          self.send_simple(@remote, sender, Java::NetJavaOtr4jIo::SerializationUtils.toString(msg))
        end


      # Authenticated, need to decrypt messages
      elsif otr[:state] == :authed
        msg = otr[:self_impl].transformReceiving(otr[:self_session], body)

        # Encryption status changed
        if !msg || otr[:self_impl].getSessionStatus(otr[:self_session]) != ENCRYPTED
          debug "*** OTR LINK SEVERED for #{sender}/#{receiver}"

          @otr_states.delete(sender)
          self.send_message(@local, doc, "[WARNING] OTR severed, no longer encrypting.")

        # Decrypted
        elsif msg != body
          # Fix bad Adium that sends <FONT> tags
          msg = msg.gsub(/<FONT>|<\/FONT>/, "")
          self.send_message(@local, doc, "[+] " << msg)

        # Failed to decrypt
        else
          self.send_message(@local, doc, "[FAILED TO DECRYPT] " << msg)
        end

      # Unknown OTR state, need to restart the session
      elsif !otr[:state]
        debug "*** Unknown state, restarting encryption"

        otr = self.initialize_otr(sender, receiver)
        otr[:pending_msg] = true
      end
    end

    nil
  end

  # Senders
  def construct_chat(from, to, msg)
    data = <<XML
<message type="chat" id="#{self.generateMsgID}" to="#{to}"#{from ? " from=\"#{from}\"" : ""}><active xmlns="http://jabber.org/protocol/chatstates"/><body>#{msg}</body></message>
XML
    data.strip!
    data.force_encoding(Encoding::ASCII_8BIT)
  end

  def send_message(target, doc, msg)
    # Replace message with unencrypted version
    body = doc.xpath("/message//body").first
    body.content = msg

    msg = doc.to_xml.split("\n", 2).last

    verbose "[out #{target == @local ? :local : :remote}] #{msg}"
    target.write(msg)
  end

  def send_simple(target, sent_from, msg)
    data = self.construct_chat(@jid[:full], sent_from, msg)

    verbose "[out #{target == @local ? :local : :remote}] #{data}"
    target.write(data)
  end

  # If the target is local, we send it to remote so it gets
  # forwarded to local as if it was a real request
  def send_raw(target, data)
    verbose "[outraw #{target == @local ? :local : :remote}] #{data}"
    target.write(data)
  end

  # Reset typing status
  def reset_typing_status(target, send_to)
    data = <<XML
<message to="#{send_to}" type="chat" id="#{self.generateMsgID}"><active xmlns="http://jabber.org/protocol/chatstates"/></message>
XML

    target.write(data.strip)
  end

  # Message IDs
  def generateMsgID
    rand(30 ** 30).to_s(16)
  end

  # Debug output
  #def verbose(msg=""); debug msg end
  #def debug(msg=""); puts msg end
  def verbose(*args); end
  def debug(*args); end
end
