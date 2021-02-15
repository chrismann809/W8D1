class User < ApplicationRecord
    validates :username, :session_token, presence: true, uniqueness: true
    validate :password, length: {minimum: 6, allow_nil: true}
    validates :password_digest, presence: true

    attr_reader :password

    def password=(password)
        @password = password
        self.password_digest = BCrypt::Password.create(password)
    end

    def is_password?(password)
        pass_check = BCrypt::Password.new(self.password_digest)
        pass_check.is_password?(password)
    end
end
