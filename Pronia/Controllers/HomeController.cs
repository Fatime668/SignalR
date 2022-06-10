using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pronia.DAL;
using Pronia.Models;
using Pronia.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Pronia.Controllers
{
    public class HomeController : Controller
    {
        private readonly AppDbContext _context;

        public HomeController(AppDbContext context)
        {
            _context = context;
        }
        public async Task<IActionResult> Index()
        {
            HomeVM model = new HomeVM
            {
                Sliders = await _context.Sliders.OrderBy(s => s.Order).Take(3).ToListAsync(),
                Plants = await _context.Plants.Include(p => p.PlantImages).Take(8).ToListAsync(),
                Clients = await _context.Clients.ToListAsync(),
                AnotherSetting = await _context.AnotherSettings.FirstOrDefaultAsync()
              };
            
            return View(model);
        }
        public async Task<IActionResult> Partial()
        {
            List<Plant> plants = await _context.Plants.Include(p => p.PlantImages).ToListAsync();
            return PartialView("_ProductPartialView", plants);
        }
    }
}
