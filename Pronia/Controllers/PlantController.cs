using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using Pronia.DAL;
using Pronia.Models;
using Pronia.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Pronia.Controllers
{
    public class PlantController : Controller
    {
        private readonly AppDbContext _context;

        public PlantController(AppDbContext context)
        {
            _context = context;
        }
        public async Task<IActionResult> Index(int page=1)
        {
            var query =  _context.Plants.AsQueryable();
            ViewBag.TotalPage = Math.Ceiling((decimal)await query.CountAsync())/3;
            ViewBag.CurrentPage = page;
            List<Plant> plants = await query.Include(p => p.PlantImages).Skip((page-1)*3).Take(3).ToListAsync();
            return View(plants);
        } 
        public async Task<IActionResult> AddBasket(int id)
        {
            Plant plant = await _context.Plants.FirstOrDefaultAsync(p=>p.Id==id);
            if (plant == null) return NotFound();
            string basketStr = HttpContext.Request.Cookies["Basket"];
            List<BasketCookieItemVM> basket;
         
            if (string.IsNullOrEmpty(basketStr))
            {
                basket = new List<BasketCookieItemVM>();
                BasketCookieItemVM cookie = new BasketCookieItemVM 
                {
                    Id = plant.Id,
                    Count = 1
                };

                basket.Add(cookie);

                basketStr = JsonConvert.SerializeObject(basket);
               

            }
            else
            {
                basket = JsonConvert.DeserializeObject<List<BasketCookieItemVM>>(basketStr);
                BasketCookieItemVM existedCookie = basket.FirstOrDefault(c => c.Id == plant.Id);
                if (existedCookie == null)
                {
                    BasketCookieItemVM cookie = new BasketCookieItemVM
                    {
                        Id = plant.Id,
                        Count = 1
                    };
                    basket.Add(cookie);
                }
                else
                {
                    existedCookie.Count++;
                }
              
                basketStr = JsonConvert.SerializeObject(basket);
            }
            HttpContext.Response.Cookies.Append("Basket", basketStr);
            
            
            return RedirectToAction("Index","Home");
        }
        public async Task<IActionResult> removeBasket(int id)
        {
            //Plant plant = await _context.Plants.FirstOrDefaultAsync(p => p.Id == id);
            string basketStr = HttpContext.Request.Cookies["Basket"];
            List<BasketCookieItemVM> basket;

            if (!string.IsNullOrEmpty(basketStr))
            {
                basket = JsonConvert.DeserializeObject<List<BasketCookieItemVM>>(basketStr);
                BasketCookieItemVM existedCookie = basket.FirstOrDefault(c => c.Id == id);
                if (existedCookie != null)
                {
                    basket.Remove(existedCookie);
                }

                basketStr = JsonConvert.SerializeObject(basket);


            }
           
            HttpContext.Response.Cookies.Append("Basket", basketStr);
           
            return RedirectToAction("Index", "Home");
        }
        public  IActionResult ShowBasket()
        {
            return Content(HttpContext.Request.Cookies["Basket"]);
        }
    }
}
