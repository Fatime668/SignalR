using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Pronia.Models;
using Pronia.Utilities;
using Pronia.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Pronia.Controllers
{

    public class AccountController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AccountController(UserManager<AppUser> userManager,SignInManager<AppUser> signInManager,RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }
        public IActionResult Register()
        {
            return View();
        }
        [HttpPost]
        [AutoValidateAntiforgeryToken]
        public async Task<IActionResult> Register(RegisterVM register)
        {
            if (!ModelState.IsValid) return View();
            AppUser user = new AppUser
            {
                FirstName = register.FirstName,
                LastName = register.LastName,
                Email = register.Email,
                UserName = register.Username
            };
            
           
            if (register.TermsCondition)
            {

                IdentityResult result = await _userManager.CreateAsync(user, register.Password);
                if (!result.Succeeded)
                {
                    foreach (IdentityError error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return View();
                }

                await _userManager.AddToRoleAsync(user, Roles.Member.ToString());

                await _signInManager.SignInAsync(user, false);
                return RedirectToAction("Index", "Home");

            }
            else
            {
                ModelState.AddModelError("", "Please accept term and condition");
                return View();
            }
        }
        public IActionResult Login()
        {
            return View();
        }
        [HttpPost]
        [AutoValidateAntiforgeryToken]
        public async Task<IActionResult> Login(LoginVM login)
        {
            AppUser user = await _userManager.FindByNameAsync(login.Username);
            if (user == null) return View();

            IList<string> roles = await _userManager.GetRolesAsync(user);
            string role = roles.FirstOrDefault(r => r.ToLower().Trim() == Roles.Member.ToString().ToLower().Trim());
            if (role == null) 
            {
                ModelState.AddModelError("", "Something went wrong. Please contact with admin");
                return View();
            }
            else
            {
                if (login.RememberMe)
                {
                    Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.PasswordSignInAsync(user, login.Password, true, true);

                    if (!result.Succeeded)
                    {
                        if (result.IsLockedOut)
                        {
                            ModelState.AddModelError("", "You have been dismissed for 5 minutes");
                            return View();
                        }
                        ModelState.AddModelError("", "Username or Password is incorrect");
                        return View();
                    }
                }
                else
                {
                    Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.PasswordSignInAsync(user, login.Password, false, true);
                    if (!result.Succeeded)
                    {
                        if (result.IsLockedOut)
                        {
                            ModelState.AddModelError("", "You have been dismissed for 5 minutes");
                            return View();
                        }
                        ModelState.AddModelError("", "Username or Password is incorrect");
                        return View();
                    }
                }

                return RedirectToAction("Index", "Home");
            }
            
        }
        [Authorize(Roles = "Member")]

        public async Task<IActionResult> Edit()
        {

            AppUser user = await _userManager.FindByNameAsync(User.Identity.Name);
            if (user == null) return NotFound();
            EditUserVM edit = new EditUserVM
            {
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                Username = user.UserName
            
            };

            return View(edit);
        }
        [HttpPost]
        [AutoValidateAntiforgeryToken]
        public async Task<IActionResult> Edit(EditUserVM user)
        {
            
            AppUser existedUser = await _userManager.FindByNameAsync(User.Identity.Name);
            EditUserVM edit = new EditUserVM
            {
                FirstName = existedUser.FirstName,
                LastName = existedUser.LastName,
                Email = existedUser.Email,
                Username = existedUser.UserName

            };
            if (!ModelState.IsValid) return View(edit);

            bool result = user.Password == null && user.ConfirmPassword == null && user.CurrentPassword != null;

            if (user.Email == null || user.Email != existedUser.Email)
            {
                ModelState.AddModelError("", "You can't change your email");
                return View(edit);
            }
            if (result)
            {
                existedUser.UserName = user.Username;
                existedUser.FirstName = user.FirstName;
                existedUser.LastName = user.LastName;
                await _userManager.UpdateAsync(existedUser);
            }
            else
            {
                existedUser.UserName = user.Username;
                existedUser.FirstName = user.FirstName;
                existedUser.LastName = user.LastName;

                if (user.CurrentPassword == user.Password)
                {
                    ModelState.AddModelError("", "You can't change password with the same password");
                    return View();
                }

                IdentityResult resultEdit = await _userManager.ChangePasswordAsync(existedUser, user.CurrentPassword, user.Password);
                if (!resultEdit.Succeeded)
                {
                    foreach (IdentityError error in resultEdit.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }
                    return View(edit);

                }
            }

            return RedirectToAction("Index", "Home");
        }
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index","Home");
        }
        public IActionResult Show()
        {
            return Content(User.Identity.IsAuthenticated.ToString());
        }
        public async Task CreateRoles()
        {
            await _roleManager.CreateAsync(new IdentityRole {Name = Roles.Member.ToString() });
            await _roleManager.CreateAsync(new IdentityRole { Name = Roles.Admin.ToString() });
            await _roleManager.CreateAsync(new IdentityRole { Name = Roles.SuperAdmin.ToString() });
        }
    }
}
