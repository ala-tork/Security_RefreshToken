using Microsoft.AspNetCore.Identity;

namespace RefreshToken.Model
{
    public class User:IdentityUser
    {
        public string? CIN { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
    }
}
