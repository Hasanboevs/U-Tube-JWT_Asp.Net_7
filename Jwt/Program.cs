using Jwt.Core.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using System.Text;

var builder = WebApplication.CreateBuilder(args);


// DB Context

var connection = builder.Configuration.GetConnectionString("MyConnection");

builder.Services.AddDbContext<AppDbContext>(options =>
options.UseNpgsql(connection)

) ;


// Add Identity

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
				.AddEntityFrameworkStores<AppDbContext>()
				.AddDefaultTokenProviders() ;





// Cinfig Identity

builder.Services.Configure<IdentityOptions>(options =>
{
	options.Password.RequiredLength = 8;
	options.Password.RequireDigit = false;
	options.Password.RequireLowercase = false;
	options.Password.RequireUppercase = false;
	options.Password.RequireNonAlphanumeric = false;
	options.SignIn.RequireConfirmedEmail = false;
});



// Add Authentication and JWT Bearer 


builder.Services.
		AddAuthentication(options =>
		{
			options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
			options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
			options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
		})
		.AddJwtBearer(options =>
		{
			options.SaveToken = true;
			options.RequireHttpsMetadata = false;
			options.TokenValidationParameters = new TokenValidationParameters()
			{
				ValidateIssuer = true,
				ValidateAudience = true,
				ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
				ValidAudience = builder.Configuration["JWT:ValidAudience"],
				IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]))
			};
		});




builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(option =>
{
	option.SwaggerDoc("v1", new OpenApiInfo { Title = "Hasanboevs", Version = "v1" });
	option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
	{
		In = ParameterLocation.Header,
		Description = "Please enter a valid token",
		Name = "Authorization",
		Type = SecuritySchemeType.Http,
		BearerFormat = "JWT",
		Scheme = "Bearer"
	});
	option.AddSecurityRequirement(new OpenApiSecurityRequirement
	{
		{
			new OpenApiSecurityScheme
			{
				Reference = new OpenApiReference
				{
					Type=ReferenceType.SecurityScheme,
					Id="Bearer"
				}
			},
			new string[]{}
		}
	});
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
	app.UseSwagger();
	app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
