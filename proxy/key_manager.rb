class KeyManager
  def initialize
    root = File.expand_path("~/Library/Application Support/otr-proxy")
    FileUtils.mkdir(root) rescue nil

    @path = root << "/otr.keys"
    @data = YAML::load_file(@path) rescue {}

    @otr_crypto = Java::NetJavaOtr4jCrypto::OtrCryptoEngineImpl.new
  end

  # Pair keys
  def hasPairByAddresses?(account, user)
    id = account.split("/", 2).first + "_XMPP_" + user
    #puts "*** HAS PAIR CHECK #{id}"

    !!@data[Digest::SHA256.hexdigest(id)]
  end

  def createPairID(session)
    id = session.getAccountID().split("/", 2).first + "_" + session.getProtocolName() + "_" + session.getUserID()
    #puts "*** PAIR ID #{id}"
    Digest::SHA256.hexdigest(id)
  end

  def loadPair(id)
    if @data[id]
      private = java.security.spec.PKCS8EncodedKeySpec.new(@data[id][:private].to_java(:byte))
      public = java.security.spec.X509EncodedKeySpec.new(@data[id][:public].to_java(:byte))

      factory = java.security.KeyFactory.getInstance("DSA")
      java.security.KeyPair.new(factory.generatePublic(public), factory.generatePrivate(private))
    end
  end

  def hasPair?(id)
    !!@data[id]
  end

  def savePair(id, pair)
    @data[id] = {
      :private => pair.getPrivate().getEncoded().to_a,
      :public => pair.getPublic().getEncoded().to_a
    }

    flush
  end

  # Remote keys
  def createRemoteID(session)
    #puts "*** REMOTE ID #{session.getAccountID()}"
    Digest::SHA256.hexdigest(session.getAccountID() + "remote")
  end

  def hasRemote?(id)
    @data[id] && @data[id][:remote]
  end

  def saveRemote(id, public)
    @data[id] = {
      :remote => true,
      :public => public.getEncoded().to_a
    }

    flush
  end

  def loadRemote(id)
    if @data[id] and @data[id][:remote]
      public = java.security.spec.X509EncodedKeySpec.new(@data[id][:public].to_java(:byte))

      factory = java.security.KeyFactory.getInstance("DSA")
      factory.generatePublic(public)
    end
  end

  def readablePublic(public)
    @otr_crypto.getFingerprint(public).gsub(/([0-9a-zA-Z]{8})/, '\1 ').strip
  end

  private
  def flush
    File.open(@path, "w+") do |f|
      f.write(@data.to_yaml)
    end
  end
end