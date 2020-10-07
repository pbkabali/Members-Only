class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  validates :username, :email, :password, presence: true 
  validates :username, :email, uniqueness: true
  validates :username, :password, length: { in: 4..10 }
end
