using JwtRoleBasedAccessControl.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtRoleBasedAccessControl.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class AuthenticationController : ControllerBase
    {
        private readonly JwtSettings _jwtSettings;
        private static int _nextId = 4;

        public AuthenticationController(IOptions<JwtSettings> jwtSettings)
        {
            _jwtSettings = jwtSettings.Value;
        }

        // Kullanıcı girişi için endpoint
        [AllowAnonymous]
        [HttpPost("Login")]
        public IActionResult Login([FromBody] ApiUser apiUserDetails)
        {
            // Kullanıcıyı kimlik doğrulaması ile kontrol et
            var apiUser = AuthenticateUser(apiUserDetails);
            if (apiUser == null) return NotFound("User not found");

            // JWT oluştur ve kullanıcıya geri döndür
            var token = GenerateToken(apiUser);
            return Ok(token);
        }

        // Yeni kullanıcı kaydı için endpoint
        [AllowAnonymous]
        [HttpPost("Register")]
        public IActionResult Register([FromBody] ApiUser newUserDetails)
        {
            // Kullanıcı adının benzersizliğini kontrol et
            if (ApiUsers.Users.Any(x => x.UserName.ToLower() == newUserDetails.UserName.ToLower()))
            {
                return Conflict("This username already exists");
            }

            // Yeni kullanıcı oluştur
            var newUser = new ApiUser
            {
                Id = _nextId++, // Otomatik ID atama
                UserName = newUserDetails.UserName,
                Password = newUserDetails.Password,
                Role = "StandardUser"
            };

            // Yeni kullanıcıyı listeye ekle
            ApiUsers.Users.Add(newUser);

            // Yeni kullanıcı için JWT oluştur ve geri döndür
            var token = GenerateToken(newUser);
            return Ok(token);
        }

        // JWT token oluşturma fonksiyonu
        private string GenerateToken(ApiUser apiUser)
        {
            // JWT ayarlarını kontrol et
            if (_jwtSettings == null) throw new Exception("The Key value in jwt settings cannot be null");

            // Güvenlik anahtarını oluştur
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // JWT içeriği için iddia (claim) listesi oluştur
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, apiUser.UserName),
                new Claim(ClaimTypes.Role, apiUser.Role!),
            };

            // JWT tokeni oluştur
            var token = new JwtSecurityToken(_jwtSettings.Issuer,
                _jwtSettings.Audience,
                claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: credentials);

            // Oluşturulan tokeni döndür
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // Kullanıcı kimlik doğrulama fonksiyonu
        private ApiUser? AuthenticateUser(ApiUser apiUserDetails)
        {
            // Kullanıcıyı kimlik bilgileri ile veritabanında kontrol et
            return ApiUsers
                .Users
                .FirstOrDefault(x =>
                    x.UserName?.ToLower() == apiUserDetails.UserName.ToLower() &&
                    x.Password == apiUserDetails.Password);
        }
    }
}
