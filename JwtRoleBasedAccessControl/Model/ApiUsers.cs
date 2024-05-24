namespace JwtRoleBasedAccessControl.Model
{
    public class ApiUsers
    {
        public static List<ApiUser> Users = new()
        {
            new ApiUser {Id = 1, UserName = "admin", Password = "123456", Role = "Administrator"},
            new ApiUser {Id = 2, UserName = "user", Password = "123456", Role = "StandardUser"},
            new ApiUser {Id = 3, UserName = "manager", Password = "123456", Role = "Manager"},
        };
    }
}
