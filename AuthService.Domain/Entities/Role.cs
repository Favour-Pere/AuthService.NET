using AuthService.Domain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthService.Domain.Entities
{
    public class Role : BaseEntity
    {
        public string Name { get; private set; } = string.Empty;

        public string? Description { get; private set; }

        public ICollection<User> Users { get; private set; } = [];

        private Role()
        { }

        public Role(string name, string? description = null)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException("Role name cannot be empty.", nameof(name));
            }
            Name = name;
            Description = description;
        }

        public void UpdateDescription(string description)
        {
            Description = description;
            MarkUpdated();
        }
    }
}