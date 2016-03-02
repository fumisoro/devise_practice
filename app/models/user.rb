class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable, :omniauthable, omniauth_providers: [:twitter]

  class << self
    def from_omniauth(auth)
      where(auth.slice(:provider, :uid)).first_or_create do |user|
        user.username = auth.info.nickname
        nser.email = auth.info.email
end
