  window.requestAnimFrame = (function() {
      return  window.requestAnimationFrame       ||
              window.webkitRequestAnimationFrame ||
              window.mozRequestAnimationFrame    ||
              window.oRequestAnimationFrame      ||
              window.msRequestAnimationFrame     ||
              function( callback ){
                window.setTimeout(callback, 1000 / 60);
              };
  })();

  window.onload = function run() {

      var width         = window.innerWidth;
      var height        = window.innerHeight;
      var elm           = document.createElement('canvas');
      var pixelDensity  = window.devicePixelRatio || 1;
      var orbs          = [];
      var orbCount      = window.innerHeight / 20;
      elm.setAttribute('width', width * pixelDensity);
      elm.setAttribute('height', height * pixelDensity);

      elm.style.width = width + "px";
      elm.style.height = height + "px";

      var ctx     = elm.getContext('2d');

      document.body.appendChild(elm);

      function generateOrbs() {
        orbs = [];
        i = 0;
        while(i < orbCount) {
          orbs[i] = new orb;
          ++i;
        }
      }

      window.addEventListener('resize', resize);

      function resize() {
          width         = window.innerWidth;
          height        = window.innerHeight;
          orbCount      = window.innerHeight / 20;
          elm.setAttribute('width', width * pixelDensity);
          elm.setAttribute('height', height * pixelDensity);
          elm.style.width = width + "px";
          elm.style.height = height + "px";
          generateOrbs();
          generateOrbConnections();
      }

      function generateOrbConnections() {
        for(var i = 0; i < orbs.length; ++i) {
          var connections = ~~(Math.random() * 5);
          (function generateConnection() {
            var connectTo = ~~(Math.random()*orbs.length);
            if ((orbs[i].connections.indexOf(orbs[connectTo])) != -1) {
              generateConnection();
            } else {
              orbs[i].connections.push(orbs[connectTo]);
            }
          })();
        }
      }

      function orb() {
        this.radius = 15;
        this.connections = [];
        this.color = ['#FF9933', '#008000'][~~(Math.random() * 2)];
        this.x = ~~(Math.random()*(elm.width-this.radius)+this.radius);
        this.y = ~~(Math.random()*(elm.height-this.radius)+this.radius);
        this.xVelocity = (~~(Math.random() * 15)) * ((~~(Math.random()*2) == 0) ? -1 : 1);
        this.yVelocity = (~~(Math.random() * 20)) * ((~~(Math.random()*2) == 0) ? -1 : 1);

        return this;
      }

      orb.prototype.draw = function() {
        ctx.fillStyle = this.color;
        ctx.strokeStyle= this.color;

        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2, 1);
        ctx.fill();
        ctx.closePath();
        for(var i = 0; i < this.connections.length; ++i) {
          ctx.beginPath();
          ctx.moveTo(this.x, this.y);
          ctx.lineTo(this.connections[i].x, this.connections[i].y);
          ctx.stroke();
          ctx.closePath();
        }
      };

      orb.prototype.move = function() {
        if (this.x + this.xVelocity +this.radius >= elm.width || this.x + this.xVelocity <= 0) {
          this.xVelocity && (this.xVelocity -= Math.random() * 2)
          this.xVelocity*=-1;
        }
        if (this.y + this.yVelocity < 0 || this.y + this.yVelocity + this.radius >= elm.height) {
          this.xVelocity && (this.yVelocity -= Math.random() * 2)

          this.yVelocity*=-1;
        }

        this.x+=this.xVelocity;
        this.y+=this.yVelocity;
        this.draw();
      }

      function tick() {
        requestAnimFrame(tick);
        ctx.clearRect(0, 0, elm.width, elm.height);
        for(var i = 0; i < orbs.length;++i) {
          orbs[i].move();
        }
      }

      generateOrbs();
      generateOrbConnections();
      tick();
}