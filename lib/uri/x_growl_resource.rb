class URI::XGrowlResource < URI::Generic

  DEFAULT_PORT = nil

  COMPONENT = [ :scheme, :unique_id ]

  UNIQUE_ID_REGEXP = /\A[\w-]+\z/

  attr_reader :unique_id

  def self.build args
    tmp = URI::Util.make_components_hash self, args

    if tmp[:unique_id] then
      tmp[:host] = tmp[:unique_id]
    else
      tmp[:host] = ''
    end

    super tmp
  end

  def initialize *args
    super

    @unique_id = nil

    if UNIQUE_ID_REGEXP =~ @host then
      if args[-1] then # arg_check
        self.unique_id = @host
      else
        set_unique_id @host
      end
    else
      raise URI::InvalidComponentError,
        "unrecognized opaque part for x-growl-resource URL: #{@host}"
    end
  end

  def to_s # :nodoc:
    "#{@scheme}://#{@unique_id}"
  end

  def unique_id= v
    check_unique_id v
    set_unique_id v
  end

  # :stopdoc:

  protected

  def set_unique_id v
    @unique_id = v
  end

  private

  def check_unique_id v
    return true unless v
    return true if v.empty?

    if parser.regexp[:HOST] !~ v or UNIQUE_ID_REGEXP !~ v then
      raise InvalidComponentError,
        "bad component (expected unique ID component): #{v}"
    end

    true
  end

end

module URI # :nodoc:
  @@schemes['X-GROWL-RESOURCE'] = URI::XGrowlResource
end

