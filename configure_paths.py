import json
import os
from pathlib import Path
from src.config import AppConfig

def main():
    config_path = AppConfig.default_path()
    if not config_path.exists():
        print(f"Error: No se encontró el archivo de configuración en {config_path}")
        return

    # Cargar configuración
    with open(config_path, "r", encoding="utf-8") as f:
        config_data = json.load(f)

    while True:
        print("\n--- Gestor de Carpetas Permitidas (personal-mcp) ---")
        print("1. Listar rutas permitidas")
        print("2. Añadir nueva ruta")
        print("3. Eliminar ruta")
        print("4. Salir")
        
        choice = input("\nSeleccione una opción: ").strip()

        if choice == "1":
            paths = config_data.get("security", {}).get("paths_allow", [])
            if not paths:
                print("\nNo hay rutas permitidas configuradas.")
            else:
                print("\n Rutas permitidas actualmente:")
                for i, p in enumerate(paths, 1):
                    print(f"{i}. {p}")

        elif choice == "2":
            new_path = input("\nIngrese la ruta completa de la carpeta a permitir: ").strip()
            if not new_path:
                print("Error: La ruta no puede estar vacía.")
                continue
            
            try:
                # Normalizar la ruta (resolve)
                resolved_path = str(Path(new_path).resolve())
                paths = config_data.get("security", {}).get("paths_allow", [])
                if resolved_path in paths:
                    print("La ruta ya está en la lista permitida.")
                else:
                    # Asegurar que la estructura exista
                    if "security" not in config_data:
                        config_data["security"] = {}
                    if "paths_allow" not in config_data["security"]:
                        config_data["security"]["paths_allow"] = []
                    
                    config_data["security"]["paths_allow"].append(resolved_path)
                    with open(config_path, "w", encoding="utf-8") as f:
                        json.dump(config_data, f, indent=2, ensure_ascii=False)
                    print(f"✅ Ruta añadida correctamente: {resolved_path}")
            except Exception as e:
                print(f"Error al procesar la ruta: {e}")

        elif choice == "3":
            paths = config_data.get("security", {}).get("paths_allow", [])
            if not paths:
                print("\nNo hay rutas para eliminar.")
                continue
            
            for i, p in enumerate(paths, 1):
                print(f"{i}. {p}")
            
            try:
                idx = int(input("\nIngrese el número de la ruta a eliminar: ")) - 1
                if 0 <= idx < len(paths):
                    removed = paths.pop(idx)
                    config_data["security"]["paths_allow"] = paths
                    with open(config_path, "w", encoding="utf-8") as f:
                        json.dump(config_data, f, indent=2, ensure_ascii=False)
                    print(f"✅ Ruta eliminada: {removed}")
                else:
                    print("Error: Número fuera de rango.")
            except ValueError:
                print("Error: Debe ingresar un número válido.")

        elif choice == "4":
            print("Saliendo...")
            break
        else:
            print("Opción no válida, intente de nuevo.")

if __name__ == "__main__":
    main()
