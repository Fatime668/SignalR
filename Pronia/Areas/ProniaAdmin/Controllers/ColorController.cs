using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Pronia.DAL;
using Pronia.Models;
using Pronia.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Pronia.Areas.ProniaAdmin.Controllers
{
    [Area("ProniaAdmin")]
    public class ColorController : Controller
    {
        private readonly AppDbContext _context;

        public ColorController(AppDbContext context)
        {
            _context = context;
        }
        public async Task<IActionResult> Index()
        {
            List<Color> colors = await _context.Colors.ToListAsync();
            return View(colors);
        }
        public IActionResult Create()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> Create(Color color)
        {
            if (!ModelState.IsValid) return View();

            await _context.Colors.AddAsync(color);
            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
        public async Task<IActionResult> Detail(int id)
        {
            Color color = await _context.Colors.FirstOrDefaultAsync(s => s.Id == id);
            if (color == null) return NotFound();

            return View(color);
        }
        public async Task<IActionResult> Edit(int id)
        {
            Color color = await _context.Colors.FirstOrDefaultAsync(s => s.Id == id);
            if (color == null) return NotFound();
            return View(color);
        }
        [HttpPost]
        public async Task<IActionResult> Edit(int id,Color color)
        {
            Color existedColor = await _context.Colors.FirstOrDefaultAsync(s => s.Id == id);
            if (existedColor == null) return NotFound();
            if (id != color.Id) return BadRequest();
            existedColor.Name = color.Name;
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Delete(int id)
        {

            Color color = await _context.Colors.FirstOrDefaultAsync(s => s.Id == id);
            if (color == null) return NotFound();
            return View(color);
        }
        [HttpPost]
        [ActionName("Delete")]
        public async Task<IActionResult> DeleteColor(int id)
        {
            Color color = await _context.Colors.FirstOrDefaultAsync(s => s.Id == id);
            if (color == null) return NotFound();
            _context.Colors.Remove(color);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }
    }
}
