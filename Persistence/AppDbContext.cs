using Microsoft.EntityFrameworkCore;

namespace OAuthExample.Persistence;

public class AppDbContext: DbContext
{
    public AppDbContext(DbContextOptions options)
        : base(options)
    {
    }
}