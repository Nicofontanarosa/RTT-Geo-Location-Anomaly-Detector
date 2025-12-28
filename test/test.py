import matplotlib.pyplot as plt
import cartopy.crs as ccrs
import cartopy.feature as cfeature
from shapely.geometry import Polygon as ShapelyPolygon
from cartopy.feature import ShapelyFeature

# Coordinates of continents
continents = {
    "Oceania": [
        (-11.88, 110), (33.13, 140), (-5, 165), (-5, 180),
        (-52.5, 180), (-52.5, 142.5), (-31.88, 110)
    ],
    "Antarctica": [
        (-60, -180), (-60, 180), (-90, 180), (-90, -180)
    ],
    "Africa": [
        (15, -30), (28.25, -13), (35.42, -10), (38, 10),
        (33, 27.5), (31.74, 34.58), (29.54, 34.92),
        (27.78, 34.46), (11.3, 44.3), (12.5, 52),
        (-60, 75), (-60, -30)
    ],
    "Europe": [
        (90, -10), (90, 77.5), (42.5, 48.8), (42.5, 30),
        (40.79, 28.81), (41, 29), (40.55, 27.31), (40.4, 26.75),
        (40.05, 26.36), (39.17, 25.19), (35.46, 27.91), (33, 27.5),
        (38, 10), (35.42, -10), (28.25, -13), (15, -30),
        (57.5, -37.5), (78.13, -10)
    ],
    "North-America": [
        (90, -168.75), (90, -10), (78.13, -10), (57.5, -37.5),
        (15, -30), (15, -75), (1.25, -82.5), (1.25, -105),
        (51, -180), (60, -180), (60, -168.75)
    ],
    "South-America": [
        (1.25, -105), (1.25, -82.5), (15, -75), (15, -30),
        (-60, -30), (-60, -105)
    ],
    "Asia": [
        (90, 77.5), (42.5, 48.8), (42.5, 30), (40.79, 28.81),
        (41, 29), (40.55, 27.31), (40.4, 26.75), (40.05, 26.36),
        (39.17, 25.19), (35.46, 27.91), (33, 27.5), (31.74, 34.58),
        (29.54, 34.92), (27.78, 34.46), (11.3, 44.3), (12.5, 52),
        (-60, 75), (-60, 110), (-31.88, 110), (-11.88, 110),
        (33.13, 140), (51, 166.6), (60, 180),
        (90, 180)
    ]
}

# Create the figure with Robinson projection
fig = plt.figure(figsize=(20, 10))
ax = plt.axes(projection=ccrs.Robinson())
ax.set_global()

# Add coastlines, borders, and gridlines
ax.coastlines(resolution='110m', linewidth=1, color='black')
ax.add_feature(cfeature.BORDERS, linestyle=':', edgecolor='gray')
ax.gridlines(draw_labels=False, color='lightgray', linestyle='--', alpha=0.5)

# Add colors to land and ocean
ax.add_feature(cfeature.LAND, facecolor='#f0e6d6')     # Light land color
ax.add_feature(cfeature.OCEAN, facecolor='#a4c8e0')    # Bluish ocean color

# Add continent boundaries (red polygons)
for name, coords in continents.items():
    polygon = ShapelyPolygon([(lon, lat) for lat, lon in coords])
    feature = ShapelyFeature([polygon], ccrs.PlateCarree(), facecolor='none', edgecolor='red', linewidth=2)
    ax.add_feature(feature)
    centroid = polygon.centroid
    ax.text(centroid.x, centroid.y, name, transform=ccrs.PlateCarree(),
            horizontalalignment='center', fontsize=12, color='blue')

# Title
plt.title("World Map - Continent Boundaries", fontsize=20, weight='bold')
plt.tight_layout()

# Show the map
plt.show()
