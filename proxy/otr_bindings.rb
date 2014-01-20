class OtrEngineHost
  java_implements "net.java.otr4j.OtrEngineHost"

  attr_reader :last_injection

  def initialize(parent)
    @parent = parent
    @keystore = parent.keystore
    @policy = Java::NetJavaOtr4j::OtrPolicyImpl.new(Java::NetJavaOtr4j::OtrPolicy::OPPORTUNISTIC)
  end

  java_signature "OtrPolicy getSessionPolicy(SessionID)"
  def getSessionPolicy(sessionID)
    @policy
  end

  java_signature "void injectMessage(SessionID, String)"
  def injectMessage(sessionID, message)
    @last_injection = message
  end

  java_signature "void showError(SessionID, String)"
  def showError(sessionID, error)
    puts "ERROR #{sessionID} / #{error}"
  end

  java_signature "void showWarning(SessionID, String)"
  def showWarning(sessionID, error)
    puts "ERROR #{sessionID} / #{error}"
  end

  java_signature "void sessionStatusChanged(SessionID)"
  def sessionStatusChanged(sessionID)
    @parent.debug "STATUS CHANGE #{sessionID}"
  end

  java_signature "KeyPair getLocalKeyPair(SessionID)"
  def getLocalKeyPair(sessionID)
    id = @keystore.createPairID(sessionID)

    # Generating new keypair
    if !@keystore.hasPair?(id)
      generator = java.security.KeyPairGenerator.getInstance("DSA")
      pair = generator.genKeyPair()

      @keystore.savePair(id, pair)

      @parent.debug "** New keypair #{sessionID} generated"

    # Already have a key
    else
      @parent.debug "** Reusing keypair for #{sessionID}"
    end

    @keystore.loadPair(id)
  end

  java_signature "byte[] getLocalFingerprintRaw(SessionID sessionID)"
  def getLocalFingerprintRaw(sessionID)
    crypto = Java::NetJavaOtr4jCrypto::OtrCryptoEngineImpl.new
    crypto.getFingerprintRaw(self.getLocalKeyPair(sessionID).getPublic())
  end

  java_signature "String getFallbackMessage"
  def getFallbackMessage
    "Off-the-Record private conversation has been requested. However, you do not have a plugin to support that."
  end

  java_signature "String getReplyForUnreadableMessage"
  def getReplyForUnreadableMessage
    "You sent a message that was unable to be decrypted, please send it again."
  end

  java_signature "String unreadableMessageReceived(SessionID)"
  def unreadableMessageReceived(sessionID)
    @parent.debug "UNREADBLE REQUIRED #{sessionID}"
    "Nope!"
  end

end