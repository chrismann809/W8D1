class User < ApplicationRecord
    validates :username, :session_token, presence: true, uniqueness: true
    validates :password, length: {minimum: 6, allow_nil: true}
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

    def self.find_by_credentials(username, password)
        user = User.find_by(username: username)
        if user.is_password?(password)
            return user
        end
        false
    end

    def generate_session_token
        session_token = SecureRandom.urlsafe_base64(16)
        session_token
    end

    def reset_session_token!
        self.session_token = generate_session_token
        self.save!
        self.session_token
    end

    private

    def ensure_session_token
        self.session_token ||= generate_session_token
    end

end
