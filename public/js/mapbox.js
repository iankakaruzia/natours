/* eslint-disable */

export const displayMap = locations => {
  mapboxgl.accessToken = 'pk.eyJ1IjoiaWFua2FrYXJ1emlhIiwiYSI6ImNrMDMwMHBlMzMwODUzY3FvdTBkaXI1c2EifQ.vxL9BZWiG1q7BE1MmcuqHw';

  var map = new mapboxgl.Map({
    container: 'map',
    style: 'mapbox://styles/iankakaruzia/ck0305w770k1w1cphhu6bxmzs',
    scrollZoom: false
  });

  const bounds = new mapboxgl.LngLatBounds();

  locations.forEach(loc => {
    const el = document.createElement('div');
    el.className = 'marker';

    new mapboxgl.Marker({
      element: el,
      anchor: 'bottom'
    }).setLngLat(loc.coordinates).addTo(map);

    new mapboxgl.Popup({
      offset: 30
    })
      .setLngLat(loc.coordinates)
      .setHTML(`<p>Day ${loc.day}: ${loc.description}</p>`)
      .addTo(map)

    bounds.extend(loc.coordinates);
  });

  map.fitBounds(bounds, {
    padding: {
      top: 200,
      bottom: 150,
      left: 100,
      right: 100
    }
  });
}
